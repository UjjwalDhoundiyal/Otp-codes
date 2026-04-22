//src/controllers/auth.controller.ts

import { Request, Response } from 'express';
import { pool } from '../config/db';
import { sendOtpEmail } from '../services/email.service';
import { 
  generateSecureOtp, 
  hashOtp, 
  saveOtp, 
  checkRateLimit, 
  verifyAndConsumeOtp 
} from '../services/otp.service';
import { RowDataPacket } from 'mysql2';
import crypto from 'crypto'; // For password hashing (e.g., bcrypt/argon2 preferred, using crypto pbkdf2 for zero-dependency demonstration)

export const sendOtp = async (req: Request, res: Response) => {
  try {
    const { email, purpose } = req.body;
    if (!email || !purpose) return res.status(400).json({ error: 'Missing parameters' });

    // SECURITY: Email Enumeration Prevention for password resets
    if (purpose === 'password_reset') {
      const [users] = await pool.execute<RowDataPacket[]>('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
      if (users.length === 0) {
        // Return 200 Success immediately without doing any actual work
        return res.status(200).json({ success: true, expiresIn: 180 });
      }
    }

    try {
      await checkRateLimit(email);
    } catch (err: any) {
      if (err.message === 'RATE_LIMIT_EXCEEDED') {
        return res.status(429).json({ error: 'Too many requests. Try again later.' });
      }
    }

    const otp = generateSecureOtp();
    const otpHash = hashOtp(otp);
    
    await saveOtp(email, otpHash, purpose);
    await sendOtpEmail(email, otp, purpose);

    return res.status(200).json({ success: true, expiresIn: 180 });
  } catch (error) {
    console.error('Send OTP Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp, purpose } = req.body;
    await verifyAndConsumeOtp(email, otp, purpose);
    
    // Generates a short-lived token or simply confirms pre-verification to the frontend
    return res.status(200).json({ success: true, message: 'OTP verified successfully' });
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Verification failed' });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { email, otp, newPassword } = req.body;
    
    // 1. Verify OTP first
    await verifyAndConsumeOtp(email, otp, 'password_reset');

    // 2. Hash new password (assuming a standard SHA-256 for demo; in prod use bcrypt/argon2)
    const newPasswordHash = crypto.createHash('sha256').update(newPassword).digest('hex');

    // 3. Update database
    await pool.execute(
      `UPDATE users SET password = ? WHERE email = ?`,
      [newPasswordHash, email]
    );

    return res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Password reset failed' });
  }
};

export const registerUser = async (req: Request, res: Response) => {
  try {
    const { username, email, password, otp } = req.body;

    // 1. Verify Registration OTP
    await verifyAndConsumeOtp(email, otp, 'registration');

    // 2. Hash Password
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

    // 3. Create User and mark email as verified immediately
    await pool.execute(
      `INSERT INTO users (username, email, password, email_verified) VALUES (?, ?, ?, ?)`,
      [username, email, passwordHash, true]
    );

    return res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (error: any) {
    // Handle duplicate email/username DB errors securely without leaking structure
    if (error.code === 'ER_DUP_ENTRY') {
       return res.status(400).json({ error: 'User already exists' });
    }
    return res.status(400).json({ error: error.message || 'Registration failed' });
  }
};
