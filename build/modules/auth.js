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
exports.login_handle = login_handle;
exports.register_handle = register_handle;
exports.verify_handle = verify_handle;
exports.profile_handle = profile_handle;
exports.delete_profile = delete_profile;
exports.handle_secure_login = handle_secure_login;
exports.update_profile = update_profile;
exports.verify_login = verify_login;
exports.handle_get_verification_code = handle_get_verification_code;
exports.handle_set_new_password = handle_set_new_password;
exports.logout = logout;
const auth_1 = require("../utils/auth");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcryptjs_1 = require("bcryptjs");
const validator_1 = require("validator");
const dotenv_1 = require("dotenv");
const crypto_1 = require("crypto");
(0, dotenv_1.config)();
function login_handle(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { email, password } = req.body;
            if (!email || !password)
                throw new Error("Email and password are needed");
            if (!(0, validator_1.isEmail)(email))
                throw new Error("Email is invalid");
            const session = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
                algorithm: "HS256",
                expiresIn: "7d",
            });
            const LoginSession = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
                algorithm: "HS256",
                expiresIn: 60 * 5,
            });
            (yield (0, auth_1.login)(email, password))
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
                    .json("You will receive a verification code soon. note. this session will expire in 5 min");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function register_handle(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { name, email, password, } = req.body;
            if (!(0, validator_1.isEmail)(email))
                res.status(400).json("Email is not valid");
            else if (!(0, validator_1.matches)(name, /^[A-Za-z\s]+$/))
                throw new Error("Name is not valid");
            else if (!(0, validator_1.isStrongPassword)(password))
                throw new Error("Password is not valid, password must be strong typed { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }");
            else {
                const salt = (0, bcryptjs_1.genSaltSync)(10);
                const hashedPassword = (0, bcryptjs_1.hashSync)(password, salt);
                const id = (0, crypto_1.randomUUID)();
                const result = yield (0, auth_1.register)({
                    id,
                    name,
                    email,
                    password: hashedPassword,
                });
                if (result) {
                    const session = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
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
                }
                else {
                    throw new Error("No access");
                }
            }
        }
        catch (error) {
            res.status(401).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function verify_handle(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { code } = req.body;
            const { session } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(session);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            if (!/^\d{6}$/.test(code))
                throw new Error("Verification code is invalid");
            yield (0, auth_1.verify)(email, code);
            res.status(200).json("Success");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function profile_handle(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { session } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(session);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            const data = yield (0, auth_1.profile)(email);
            if (!data)
                throw new Error("Session is Invalid");
            res.status(200).json(data);
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function delete_profile(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { password } = req.body;
            const { session } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(session);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            const data = yield (0, auth_1.deleteProfile)(email, password);
            if (!data)
                throw new Error("Session is Invalid");
            res.clearCookie("session").status(200).json("Account Deleted Successfully");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function handle_secure_login(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { session } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(session);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            const success = yield (0, auth_1.secureLogin)(email);
            if (success)
                res.status(200).json("Success");
            else
                throw new Error("Something went wrong");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function update_profile(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { session } = req.cookies;
            const { name, image } = req.body;
            const decoded = jsonwebtoken_1.default.decode(session);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            const updates = {};
            if (name && /^[a-zA-Z\s]+$/.test(name))
                updates.name = name;
            if (image &&
                (0, validator_1.isURL)(image, { protocols: ["http", "https"], require_protocol: true }))
                updates.image = image;
            if (!updates.name && !image)
                throw new Error("invalid Entry");
            yield (0, auth_1.updateProfile)(Object.assign({ email }, updates));
            res.status(200).json("updated");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function verify_login(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { code } = req.body;
            const { login } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(login);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            if (!/^\d{6}$/.test(code))
                throw new Error("Verification code is invalid");
            yield (0, auth_1.verify)(email, code);
            const session = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
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
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function handle_get_verification_code(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { email } = req.body;
            if (!(0, validator_1.isEmail)(email))
                throw new Error("This email is Invalid");
            yield (0, auth_1.sendVCode)(email);
            const forgetPasswordSession = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
                algorithm: "HS256",
                expiresIn: 60 * 5,
            });
            res
                .cookie("resetPassword", forgetPasswordSession, {
                httpOnly: true,
                secure: true,
                sameSite: "lax",
            })
                .status(200)
                .json("You will get your Verification code soon. note. this session will expire in 5 min ");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function handle_set_new_password(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { code, password } = req.body;
            const { resetPassword } = req.cookies;
            const decoded = jsonwebtoken_1.default.decode(resetPassword);
            if (!decoded || typeof decoded !== "object" || !decoded.email) {
                throw new Error("Session is invalid");
            }
            const { email } = decoded;
            if (!(0, validator_1.isStrongPassword)(password))
                throw new Error("Password is not valid, password must be strong typed { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }");
            if (!/^\d{6}$/.test(code))
                throw new Error("Verification code is invalid");
            yield (0, auth_1.verify)(email, code);
            const session = jsonwebtoken_1.default.sign({ email }, process.env.JWT_SECRET, {
                algorithm: "HS256",
                expiresIn: "7d",
            });
            const salt = (0, bcryptjs_1.genSaltSync)(10);
            const hashedPassword = (0, bcryptjs_1.hashSync)(password, salt);
            yield (0, auth_1.resetPasswordFunc)(email, hashedPassword);
            res
                .cookie("session", session, {
                httpOnly: true,
                secure: true,
                sameSite: "lax",
            })
                .clearCookie("resetPassword")
                .status(200)
                .json("Logged in.");
        }
        catch (error) {
            res.status(400).json(`Bad Request: ${error === null || error === void 0 ? void 0 : error.message}`);
        }
    });
}
function logout(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            res
                .clearCookie("session")
                .clearCookie("login")
                .clearCookie("resetPassword")
                .status(200)
                .json("logged out.");
        }
        catch (error) {
            res.status(400).json("Something went wrong.");
        }
    });
}
