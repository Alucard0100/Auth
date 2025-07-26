"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRepo = void 0;
const db_1 = __importDefault(require("../config/db"));
class UserRepo {
    static read(email) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`SELECT * FROM user WHERE email = ?`, [email], (err, res) => {
                if (err) {
                    resolve(undefined);
                }
                else {
                    resolve(res[0]);
                }
            });
        });
    }
    static delete(email) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`Delete FROM user WHERE email = ?`, [email], (err, res) => {
                if (err) {
                    resolve(false);
                }
                else {
                    resolve(true);
                }
            });
        });
    }
    static login(email) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`SELECT password , more_secured FROM user WHERE email = ?`, [email], (err, res) => {
                if (err) {
                    resolve(undefined);
                }
                else {
                    resolve(res);
                }
            });
        });
    }
    static secureLogin(email) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`UPDATE user SET more_secured = 1 WHERE email = ?`, [email], (err, res) => {
                if (err) {
                    resolve(false);
                }
                else {
                    resolve(true);
                }
            });
        });
    }
    static UpdatePassword(email, password) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`UPDATE user SET password = ? WHERE email = ?`, [password, email], (err, res) => {
                if (err) {
                    resolve(false);
                }
                else {
                    resolve(true);
                }
            });
        });
    }
    static updateProfile(updates) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`UPDATE user SET name = ? , image = ? WHERE email = ?`, updates, (err, res) => {
                if (err) {
                    resolve(false);
                }
                else {
                    resolve(true);
                }
            });
        });
    }
    static create(user, code) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.execute("INSERT INTO user (id, email, name, password, balance, code,isVerified )\
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )", [
                user.id,
                user.email,
                user.name,
                user.password,
                user.balance,
                code,
                user.isVerified || false,
            ], (err, res) => {
                if (err) {
                    resolve(undefined);
                }
                else {
                    resolve(true);
                }
            });
        });
    }
    static getVCode({ email }) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.query(`SELECT code FROM user WHERE email = ?`, [email], (err, res) => {
                if (err)
                    resolve(false);
                else
                    resolve(res);
            });
        });
    }
    static verify(email) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.execute(`UPDATE user SET isverified = 1 WHERE email = ? `, [email], (err, res) => {
                if (err)
                    resolve(false);
                else
                    resolve(true);
            });
        });
    }
    static updateVCode(email, code) {
        return new Promise((resolve, reject) => {
            db_1.default.connection.execute(`UPDATE user SET code = ? WHERE email = ? `, [code, email], (err, res) => {
                if (err)
                    resolve(false);
                else
                    resolve(true);
            });
        });
    }
}
exports.UserRepo = UserRepo;
