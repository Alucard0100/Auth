import { User } from "../models/auth";
import { UserRepo } from "../repo/auth";
import crypto from "crypto";
import { sendVerificationCode } from "./sendEmail";
import { compareSync, genSaltSync, hashSync } from "bcryptjs";
import { isArrayBufferView } from "util/types";

export async function login(email: string, password: string): Promise<boolean> {
  const res = await UserRepo.login(email);
  if (Array.isArray(res) && res.length < 1) throw new Error("Email not found.");
  if (Array.isArray(res) && res[0].password) {
    if (compareSync(password, res[0].password)) {
      if (res[0].more_secured) {
        const newCode = crypto
          .randomInt(100000, 1000000)
          .toString()
          .padStart(6, "0");
        const salt = genSaltSync(10);
        const hashedCode = hashSync(newCode, salt);
        await Promise.all([
          UserRepo.updateVCode(email, hashedCode),
          sendVerificationCode({ email, code: newCode }),
        ]);
        return false;
      } else return true;
    } else throw new Error("Email or Password is Incorrect");
  }
  return false;
}

export async function register({
  id,
  name,
  email,
  password,
}: {
  id: string;
  name: string;
  email: string;
  password: string;
}): Promise<boolean> {
  const user: User = {
    balance: 0,
    code: crypto.randomInt(100000, 1000000).toString().padStart(6, "0"),
    id,
    name,
    password,
    isVerified: false,
    email,
    more_secured: false,
    constructor: { name: "RowDataPacket" },
    image:
      "https://st4.depositphotos.com/9998432/22597/v/450/depositphotos_225976914-stock-illustration-person-gray-photo-placeholder-man.jpg",
  };
  const salt = genSaltSync(10);
  const hashedCode = hashSync(user.code, salt);

  const result = await UserRepo.create(user, hashedCode);
  if (!result) throw new Error("This Email already exists");
  await sendVerificationCode({ email: user.email, code: user.code });

  return result;
}

export async function verify(email: string, code: string) {
  const res = await UserRepo.getVCode({ email });
  if (!Array.isArray(res)) throw new Error("An error happened");
  if (!compareSync(code, res[0].code)) {
    const newCode = crypto
      .randomInt(100000, 1000000)
      .toString()
      .padStart(6, "0");
    const salt = genSaltSync(10);
    const hashedCode = hashSync(newCode, salt);
    const res = await UserRepo.updateVCode(email, hashedCode);
    if (!res) throw new Error("And Error happened.");
    await sendVerificationCode({ email: email, code: newCode });
    throw new Error(
      "Verification code is invalid, you will receive the new verification code soon."
    );
  } else {
    const newCode = crypto
      .randomInt(100000, 1000000)
      .toString()
      .padStart(6, "0");
    const salt = genSaltSync(10);
    const hashedCode = hashSync(newCode, salt);
    await UserRepo.updateVCode(email, hashedCode);
  }
  return UserRepo.verify(email);
}

export async function profile(email: string) {
  const res = await UserRepo.read(email);

  if (!res) throw new Error("Session is Invalid");
  const { password, code, ...data } = res;
  return data;
}

export async function deleteProfile(
  email: string,
  password: string
): Promise<boolean> {
  const res = await UserRepo.login(email);
  if (Array.isArray(res) && res[0].password) {
    if (!compareSync(password, res[0].password))
      throw new Error("Password is Invalid");
    return await UserRepo.delete(email);
  }
  return false;
}

export async function secureLogin(email: string): Promise<boolean> {
  return await UserRepo.secureLogin(email);
}

export async function updateProfile({
  email,
  name,
  image,
}: {
  email: string;
  name?: string;
  image?: string;
}): Promise<boolean> {
  const res = await UserRepo.read(email);

  if (!res) throw new Error("Session is Invalid");
  const { password, code, ...data } = res;
  const updates: string[] = [];
  name ? updates.push(name) : updates.push(data.name);
  image ? updates.push(image) : updates.push(data.image);
  updates.push(email);

  return await UserRepo.updateProfile(updates);
}

export async function sendVCode(email: string) {
  const newCode = crypto.randomInt(100000, 1000000).toString().padStart(6, "0");
  const salt = genSaltSync(10);
  const hashedCode = hashSync(newCode, salt);
  await Promise.all([
    UserRepo.updateVCode(email, hashedCode),
    sendVerificationCode({ email, code: newCode }),
  ]);
}

export async function resetPasswordFunc(email: string, password: string) {
  const res = await UserRepo.UpdatePassword(email, password);
  if (!res) {
    const newCode = crypto
      .randomInt(100000, 1000000)
      .toString()
      .padStart(6, "0");
    const salt = genSaltSync(10);
    const hashedCode = hashSync(newCode, salt);
    await Promise.all([
      UserRepo.updateVCode(email, hashedCode),
      sendVerificationCode({ email, code: newCode }),
    ]);
    throw new Error("Something wrong happened, please try again later");
  }
}
