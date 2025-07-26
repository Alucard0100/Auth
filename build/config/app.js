"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = require("dotenv");
(0, dotenv_1.config)();
class Config {
}
Config.host = process.env.CONFIG_HOST;
Config.port = Number(process.env.CONFIG_PORT);
Config.secret = process.env.tutorial;
exports.default = Config;
