//src/services/email.service.ts

import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export const sendOtpEmail = async (to: string, otp: string, purpose: string): Promise<void> => {
  const subject = purpose === 'registration' 
    ? 'VoltStartEV - Complete your registration' 
    : 'VoltStartEV - Password Reset Request';
  
  const text = `Your One-Time Password is: ${otp}. It expires in 3 minutes. Do not share this code with anyone.`;

  await transporter.sendMail({
    from: `"VoltStartEV Security" <${process.env.SMTP_USER}>`,
    to,
    subject,
    text,
  });
};
