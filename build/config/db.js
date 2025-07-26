"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mysql2_1 = require("mysql2");
const dotenv_1 = require("dotenv");
(0, dotenv_1.config)();
class DatabaseConnection {
}
DatabaseConnection.connection = (0, mysql2_1.createPool)({
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
});
exports.default = DatabaseConnection;
