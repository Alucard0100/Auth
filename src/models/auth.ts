import { RowDataPacket } from "mysql2";

export interface User extends RowDataPacket {
  id: string;
  email: string;
  name:string;
  password: string;
  balance: number;
  role?: "USER" | "ADMIN";
  isVerified?: boolean;
  image: string;
  code: string;
  more_secured:boolean;
}