//src/routes/auth.routes.ts

import { Router } from 'express';
import { sendOtp, verifyOtp, resetPassword, registerUser } from '../controllers/auth.controller';

const router = Router();

// Endpoint 1: Generate & send
router.post('/api/auth/send-otp', sendOtp);

// Endpoint 2: Pre-verification 
router.post('/api/auth/verify-otp', verifyOtp);

// Endpoint 3: Reset password
router.post('/api/auth/reset-password', resetPassword);

// Endpoint 4: Register with OTP verification
router.post('/api/users', registerUser);

export default router;
