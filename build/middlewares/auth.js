"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate_session = validate_session;
exports.validate_login_session = validate_login_session;
exports.validate_rest_password_session = validate_rest_password_session;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const validator_1 = require("validator");
const dotenv_1 = require("dotenv");
(0, dotenv_1.config)();
function validate_session(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { session } = req.cookies;
            handle_validate_sessions(session, next);
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function validate_login_session(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { login } = req.cookies;
            handle_validate_sessions(login, next);
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function validate_rest_password_session(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { resetPassword } = req.cookies;
            handle_validate_sessions(resetPassword, next);
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function handle_validate_sessions(session, next) {
    if (!session)
        throw new Error("Session is invalid");
    const decoded = jsonwebtoken_1.default.verify(session, process.env.JWT_SECRET, {
        complete: true,
    });
    if (!decoded || typeof decoded !== "object" || !("email" in decoded)) {
        if (!decoded || typeof decoded !== "object") {
            throw new Error("Session is invalid");
        }
        const email = decoded.payload.email;
        if (!(0, validator_1.isEmail)(email))
            throw new Error("Session is invalid");
        next();
    }
    else
        throw new Error("Something went wrong please try again later.");
}
