import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { isEmail } from "validator";
import { config } from "dotenv";
config();

export async function validate_session(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { session } = req.cookies;
    handle_validate_sessions(session, next);
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function validate_login_session(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { login } = req.cookies;
    handle_validate_sessions(login, next);
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function validate_rest_password_session(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { resetPassword } = req.cookies;
    handle_validate_sessions(resetPassword, next);
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

function handle_validate_sessions(session: any, next: NextFunction) {
  if (!session) throw new Error("Session is invalid");
  const decoded = jwt.verify(session, process.env.JWT_SECRET as string, {
    complete: true,
  });
  if (!decoded || typeof decoded !== "object" || !("email" in decoded)) {
    if (!decoded || typeof decoded !== "object") {
      throw new Error("Session is invalid");
    }
    const email = (decoded.payload as { email: string }).email;
    if (!isEmail(email)) throw new Error("Session is invalid");
    next();
  } else throw new Error("Something went wrong please try again later.");
}
