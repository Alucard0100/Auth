import transport from "../config/smtp";
import { config } from "dotenv";
config();

export const sendVerificationCode = async ({
  email,
  code,
}: {
  email: string;
  code: string;
}) => {
  await transport.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject: "Your Email Verification Code from EM.",
    text: `Your verification code is: ${code}.`,
    html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Email Verification</h2>
          <p>Your verification code is:</p>
          <h1 style="font-size: 32px; letter-spacing: 5px; color: #4F46E5; background: #F3F4F6; padding: 20px; text-align: center; border-radius: 8px;">
            ${code}
          </h1>
          <p>If you didn't request this code, please ignore this email.</p>
        </div>
      `,
  });
};
