import { createPool } from "mysql2";
import { config } from "dotenv";
config();
export default class DatabaseConnection {
  static connection = createPool({
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
  });
}
