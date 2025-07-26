"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendVerificationCode = void 0;
const smtp_1 = __importDefault(require("../config/smtp"));
const dotenv_1 = require("dotenv");
(0, dotenv_1.config)();
const sendVerificationCode = (_a) => __awaiter(void 0, [_a], void 0, function* ({ email, code, }) {
    yield smtp_1.default.sendMail({
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
});
exports.sendVerificationCode = sendVerificationCode;
