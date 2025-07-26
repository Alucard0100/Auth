import { config } from "dotenv";
config();
export default class Config {
  static host: string = process.env.CONFIG_HOST as string;
  static port: number = Number(process.env.CONFIG_PORT);
  static secret: string = process.env.tutorial as string;
}
