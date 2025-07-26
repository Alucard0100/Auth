import { ResultSetHeader } from "mysql2";
import { User } from "../models/auth";
import DatabaseConnection from "../config/db";

export class UserRepo {
  static read(email: string): Promise<User | undefined> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `SELECT * FROM user WHERE email = ?`,
        [email],
        (err, res) => {
          if (err) {
            resolve(undefined);
          } else {
            resolve(res[0]);
          }
        }
      );
    });
  }
  static delete(email: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `Delete FROM user WHERE email = ?`,
        [email],
        (err, res) => {
          if (err) {
            resolve(false);
          } else {
            resolve(true);
          }
        }
      );
    });
  }

  static login(email: string): Promise<User[] | undefined> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `SELECT password , more_secured FROM user WHERE email = ?`,
        [email],
        (err, res) => {
          if (err) {
            resolve(undefined);
          } else {
            resolve(res);
          }
        }
      );
    });
  }
  static secureLogin(email: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `UPDATE user SET more_secured = 1 WHERE email = ?`,
        [email],
        (err, res) => {
          if (err) {
            resolve(false);
          } else {
            resolve(true);
          }
        }
      );
    });
  }
  static UpdatePassword(email: string, password: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `UPDATE user SET password = ? WHERE email = ?`,
        [password, email],
        (err, res) => {
          if (err) {
            resolve(false);
          } else {
            resolve(true);
          }
        }
      );
    });
  }

  static updateProfile(updates: string[]): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `UPDATE user SET name = ? , image = ? WHERE email = ?`,
        updates,
        (err, res) => {
          if (err) {
            resolve(false);
          } else {
            resolve(true);
          }
        }
      );
    });
  }

  static create(user: User, code: string): Promise<boolean | undefined> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.execute<ResultSetHeader>(
        "INSERT INTO user (id, email, name, password, balance, code,isVerified )\
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )",
        [
          user.id,
          user.email,
          user.name,
          user.password,
          user.balance,
          code,
          user.isVerified || false,
        ],
        (err, res) => {
          if (err) {
            resolve(undefined);
          } else {
            resolve(true);
          }
        }
      );
    });
  }
  static getVCode({ email }: { email: string }) {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.query<User[]>(
        `SELECT code FROM user WHERE email = ?`,
        [email],
        (err, res) => {
          if (err) resolve(false);
          else resolve(res);
        }
      );
    });
  }

  static verify(email: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.execute(
        `UPDATE user SET isverified = 1 WHERE email = ? `,
        [email],
        (err, res) => {
          if (err) resolve(false);
          else resolve(true);
        }
      );
    });
  }
  static updateVCode(email: string, code: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      DatabaseConnection.connection.execute(
        `UPDATE user SET code = ? WHERE email = ? `,
        [code, email],
        (err, res) => {
          if (err) resolve(false);
          else resolve(true);
        }
      );
    });
  }
}
