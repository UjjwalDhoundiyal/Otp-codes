//src/services/otp.service.ts

import crypto from 'crypto';
import { pool } from '../config/db';
import { RowDataPacket, ResultSetHeader } from 'mysql2';

type Purpose = 'registration' | 'password_reset';

/**
 * SECURITY: Generates a secure 6-digit OTP using the Node.js crypto module.
 * Math.random() is predictable and must never be used for security tokens.
 */
export const generateSecureOtp = (): string => {
  return crypto.randomInt(100000, 1000000).toString();
};

/**
 * SECURITY: Hashes the OTP using SHA-256 before database insertion.
 */
export const hashOtp = (otp: string): string => {
  return crypto.createHash('sha256').update(otp).digest('hex');
};

export const checkRateLimit = async (email: string): Promise<void> => {
  const [rows] = await pool.execute<RowDataPacket[]>(
    `SELECT COUNT(*) as count FROM otp_verifications 
     WHERE email = ? AND created_at > NOW() - INTERVAL 1 HOUR`,
    [email]
  );
  
  if (rows[0].count >= 3) {
    throw new Error('RATE_LIMIT_EXCEEDED');
  }
};

export const saveOtp = async (email: string, otpHash: string, purpose: Purpose): Promise<void> => {
  // SECURITY: Parameterized query prevents SQL Injection. Expiry strictly set to +3 minutes via DB time.
  await pool.execute(
    `INSERT INTO otp_verifications (email, otp_hash, purpose, expires_at, created_at)
     VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 3 MINUTE), NOW())`,
    [email, otpHash, purpose]
  );
};

export const verifyAndConsumeOtp = async (email: string, inputOtp: string, purpose: Purpose): Promise<boolean> => {
  const [rows] = await pool.execute<RowDataPacket[]>(
    `SELECT id, otp_hash, expires_at, used_at, attempts 
     FROM otp_verifications 
     WHERE email = ? AND purpose = ? 
     ORDER BY created_at DESC LIMIT 1`,
    [email, purpose]
  );

  if (!rows.length) throw new Error('OTP_NOT_FOUND');

  const record = rows[0];

  // SECURITY: Replay attack prevention.
  if (record.used_at !== null) throw new Error('OTP_ALREADY_USED');
  
  // SECURITY: Expiry enforcement.
  if (new Date() > new Date(record.expires_at)) throw new Error('OTP_EXPIRED');

  // SECURITY: Brute-force protection. Max 3 attempts.
  if (record.attempts >= 3) throw new Error('MAX_ATTEMPTS_REACHED');

  const inputHash = hashOtp(inputOtp);
  
  // SECURITY: Prevent timing attacks by comparing hashes in constant time
  const isMatch = crypto.timingSafeEqual(Buffer.from(inputHash, 'hex'), Buffer.from(record.otp_hash, 'hex'));

  if (!isMatch) {
    // Increment attempts
    await pool.execute(
      `UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = ?`,
      [record.id]
    );
    throw new Error('INVALID_OTP');
  }

  // SECURITY: Mark as used immediately to prevent replay attacks
  await pool.execute(
    `UPDATE otp_verifications SET used_at = NOW() WHERE id = ?`,
    [record.id]
  );

  return true;
};
