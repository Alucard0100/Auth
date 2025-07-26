import { Request, Response } from "express";
import {
  deleteProfile,
  login,
  profile,
  register,
  secureLogin,
  updateProfile,
  verify,
  sendVCode,
  resetPasswordFunc,
} from "../utils/auth";
import jwt from "jsonwebtoken";
import { hashSync, genSaltSync } from "bcryptjs";
import { isEmail, isStrongPassword, isURL, matches } from "validator";
import { config } from "dotenv";
import { randomUUID } from "crypto";
config();

export async function login_handle(req: Request, res: Response) {
  try {
    const { email, password } = req.body;
    if (!email || !password) throw new Error("Email and password are needed");
    if (!isEmail(email)) throw new Error("Email is invalid");
    const session = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      algorithm: "HS256",
      expiresIn: "7d",
    });
    const LoginSession = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      algorithm: "HS256",
      expiresIn: 60 * 5,
    });
    (await login(email, password))
      ? res
          .cookie("session", session, {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
          })
          .status(200)
          .json("Logged in.")
      : res
          .cookie("login", LoginSession, {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
          })
          .status(200)
          .json(
            "You will receive a verification code soon. note. this session will expire in 5 min"
          );
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function register_handle(req: Request, res: Response) {
  try {
    const {
      name,
      email,
      password,
    }: { name: string; email: string; password: string } = req.body;

    if (!isEmail(email)) res.status(400).json("Email is not valid");
    else if (!matches(name, /^[A-Za-z\s]+$/))
      throw new Error("Name is not valid");
    else if (!isStrongPassword(password))
      throw new Error(
        "Password is not valid, password must be strong typed { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }"
      );
    else {
      const salt = genSaltSync(10);
      const hashedPassword = hashSync(password, salt);
      const id = randomUUID();
      const result = await register({
        id,
        name,
        email,
        password: hashedPassword,
      });

      if (result) {
        const session = jwt.sign({ email }, process.env.JWT_SECRET as string, {
          algorithm: "HS256",
          expiresIn: "7d",
        });
        res
          .cookie("session", session, {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
          })
          .status(201)
          .json("Success");
      } else {
        throw new Error("No access");
      }
    }
  } catch (error: any) {
    res.status(401).json(`Bad Request: ${error?.message}`);
  }
}

export async function verify_handle(req: Request, res: Response) {
  try {
    const { code }: { code: string } = req.body;
    const { session } = req.cookies;

    const decoded = jwt.decode(session);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    if (!/^\d{6}$/.test(code)) throw new Error("Verification code is invalid");
    await verify(email, code);
    res.status(200).json("Success");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function profile_handle(req: Request, res: Response) {
  try {
    const { session } = req.cookies;

    const decoded = jwt.decode(session);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    const data = await profile(email);
    if (!data) throw new Error("Session is Invalid");
    res.status(200).json(data);
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function delete_profile(req: Request, res: Response) {
  try {
    const { password } = req.body;
    const { session } = req.cookies;

    const decoded = jwt.decode(session);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    const data = await deleteProfile(email, password);
    if (!data) throw new Error("Session is Invalid");
    res.clearCookie("session").status(200).json("Account Deleted Successfully");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function handle_secure_login(req: Request, res: Response) {
  try {
    const { session } = req.cookies;

    const decoded = jwt.decode(session);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    const success = await secureLogin(email);
    if (success) res.status(200).json("Success");
    else throw new Error("Something went wrong");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function update_profile(req: Request, res: Response) {
  try {
    const { session } = req.cookies;
    const { name, image } = req.body;

    const decoded = jwt.decode(session);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    const updates: { name?: string; image?: string } = {};
    if (name && /^[a-zA-Z\s]+$/.test(name)) updates.name = name;
    if (
      image &&
      isURL(image, { protocols: ["http", "https"], require_protocol: true })
    )
      updates.image = image;
    if (!updates.name && !image) throw new Error("invalid Entry");
    await updateProfile({ email, ...updates });
    res.status(200).json("updated");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function verify_login(req: Request, res: Response) {
  try {
    const { code }: { code: string } = req.body;
    const { login } = req.cookies;
    const decoded = jwt.decode(login);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    if (!/^\d{6}$/.test(code)) throw new Error("Verification code is invalid");

    await verify(email, code);
    const session = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      algorithm: "HS256",
      expiresIn: "7d",
    });
    res
      .cookie("session", session, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      })
      .clearCookie("login")
      .status(200)
      .json("Logged in.");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function handle_get_verification_code(
  req: Request,
  res: Response
) {
  try {
    const { email } = req.body;
    if (!isEmail(email)) throw new Error("This email is Invalid");
    await sendVCode(email);
    const forgetPasswordSession = jwt.sign(
      { email },
      process.env.JWT_SECRET as string,
      {
        algorithm: "HS256",
        expiresIn: 60 * 5,
      }
    );
    res
      .cookie("resetPassword", forgetPasswordSession, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      })
      .status(200)
      .json(
        "You will get your Verification code soon. note. this session will expire in 5 min "
      );
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function handle_set_new_password(req: Request, res: Response) {
  try {
    const { code, password } = req.body;
    const { resetPassword } = req.cookies;
    const decoded = jwt.decode(resetPassword);
    if (!decoded || typeof decoded !== "object" || !decoded.email) {
      throw new Error("Session is invalid");
    }
    const { email } = decoded;

    if (!isStrongPassword(password))
      throw new Error(
        "Password is not valid, password must be strong typed { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }"
      );

    if (!/^\d{6}$/.test(code)) throw new Error("Verification code is invalid");

    await verify(email, code);
    const session = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      algorithm: "HS256",
      expiresIn: "7d",
    });
    const salt = genSaltSync(10);
    const hashedPassword = hashSync(password, salt);
    await resetPasswordFunc(email, hashedPassword);
    res
      .cookie("session", session, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      })
      .clearCookie("resetPassword")
      .status(200)
      .json("Logged in.");
  } catch (error: any) {
    res.status(400).json(`Bad Request: ${error?.message}`);
  }
}

export async function logout(req: Request, res: Response) {
  try {
    res
      .clearCookie("session")
      .clearCookie("login")
      .clearCookie("resetPassword")
      .status(200)
      .json("logged out.");
  } catch (error: any) {
    res.status(400).json("Something went wrong.");
  }
}
