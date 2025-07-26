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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.login = login;
exports.register = register;
exports.verify = verify;
exports.profile = profile;
exports.deleteProfile = deleteProfile;
exports.secureLogin = secureLogin;
exports.updateProfile = updateProfile;
exports.sendVCode = sendVCode;
exports.resetPasswordFunc = resetPasswordFunc;
const auth_1 = require("../repo/auth");
const crypto_1 = __importDefault(require("crypto"));
const sendEmail_1 = require("./sendEmail");
const bcryptjs_1 = require("bcryptjs");
function login(email, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const res = yield auth_1.UserRepo.login(email);
        if (Array.isArray(res) && res.length < 1)
            throw new Error("Email not found.");
        if (Array.isArray(res) && res[0].password) {
            if ((0, bcryptjs_1.compareSync)(password, res[0].password)) {
                if (res[0].more_secured) {
                    const newCode = crypto_1.default
                        .randomInt(100000, 1000000)
                        .toString()
                        .padStart(6, "0");
                    const salt = (0, bcryptjs_1.genSaltSync)(10);
                    const hashedCode = (0, bcryptjs_1.hashSync)(newCode, salt);
                    yield Promise.all([
                        auth_1.UserRepo.updateVCode(email, hashedCode),
                        (0, sendEmail_1.sendVerificationCode)({ email, code: newCode }),
                    ]);
                    return false;
                }
                else
                    return true;
            }
            else
                throw new Error("Email or Password is Incorrect");
        }
        return false;
    });
}
function register(_a) {
    return __awaiter(this, arguments, void 0, function* ({ id, name, email, password, }) {
        const user = {
            balance: 0,
            code: crypto_1.default.randomInt(100000, 1000000).toString().padStart(6, "0"),
            id,
            name,
            password,
            isVerified: false,
            email,
            more_secured: false,
            constructor: { name: "RowDataPacket" },
            image: "https://st4.depositphotos.com/9998432/22597/v/450/depositphotos_225976914-stock-illustration-person-gray-photo-placeholder-man.jpg",
        };
        const salt = (0, bcryptjs_1.genSaltSync)(10);
        const hashedCode = (0, bcryptjs_1.hashSync)(user.code, salt);
        const result = yield auth_1.UserRepo.create(user, hashedCode);
        if (!result)
            throw new Error("This Email already exists");
        yield (0, sendEmail_1.sendVerificationCode)({ email: user.email, code: user.code });
        return result;
    });
}
function verify(email, code) {
    return __awaiter(this, void 0, void 0, function* () {
        const res = yield auth_1.UserRepo.getVCode({ email });
        if (!Array.isArray(res))
            throw new Error("An error happened");
        if (!(0, bcryptjs_1.compareSync)(code, res[0].code)) {
            const newCode = crypto_1.default
                .randomInt(100000, 1000000)
                .toString()
                .padStart(6, "0");
            const salt = (0, bcryptjs_1.genSaltSync)(10);
            const hashedCode = (0, bcryptjs_1.hashSync)(newCode, salt);
            const res = yield auth_1.UserRepo.updateVCode(email, hashedCode);
            if (!res)
                throw new Error("And Error happened.");
            yield (0, sendEmail_1.sendVerificationCode)({ email: email, code: newCode });
            throw new Error("Verification code is invalid, you will receive the new verification code soon.");
        }
        else {
            const newCode = crypto_1.default
                .randomInt(100000, 1000000)
                .toString()
                .padStart(6, "0");
            const salt = (0, bcryptjs_1.genSaltSync)(10);
            const hashedCode = (0, bcryptjs_1.hashSync)(newCode, salt);
            yield auth_1.UserRepo.updateVCode(email, hashedCode);
        }
        return auth_1.UserRepo.verify(email);
    });
}
function profile(email) {
    return __awaiter(this, void 0, void 0, function* () {
        const res = yield auth_1.UserRepo.read(email);
        if (!res)
            throw new Error("Session is Invalid");
        const { password, code } = res, data = __rest(res, ["password", "code"]);
        return data;
    });
}
function deleteProfile(email, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const res = yield auth_1.UserRepo.login(email);
        if (Array.isArray(res) && res[0].password) {
            if (!(0, bcryptjs_1.compareSync)(password, res[0].password))
                throw new Error("Password is Invalid");
            return yield auth_1.UserRepo.delete(email);
        }
        return false;
    });
}
function secureLogin(email) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield auth_1.UserRepo.secureLogin(email);
    });
}
function updateProfile(_a) {
    return __awaiter(this, arguments, void 0, function* ({ email, name, image, }) {
        const res = yield auth_1.UserRepo.read(email);
        if (!res)
            throw new Error("Session is Invalid");
        const { password, code } = res, data = __rest(res, ["password", "code"]);
        const updates = [];
        name ? updates.push(name) : updates.push(data.name);
        image ? updates.push(image) : updates.push(data.image);
        updates.push(email);
        return yield auth_1.UserRepo.updateProfile(updates);
    });
}
function sendVCode(email) {
    return __awaiter(this, void 0, void 0, function* () {
        const newCode = crypto_1.default.randomInt(100000, 1000000).toString().padStart(6, "0");
        const salt = (0, bcryptjs_1.genSaltSync)(10);
        const hashedCode = (0, bcryptjs_1.hashSync)(newCode, salt);
        yield Promise.all([
            auth_1.UserRepo.updateVCode(email, hashedCode),
            (0, sendEmail_1.sendVerificationCode)({ email, code: newCode }),
        ]);
    });
}
function resetPasswordFunc(email, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const res = yield auth_1.UserRepo.UpdatePassword(email, password);
        if (!res) {
            const newCode = crypto_1.default
                .randomInt(100000, 1000000)
                .toString()
                .padStart(6, "0");
            const salt = (0, bcryptjs_1.genSaltSync)(10);
            const hashedCode = (0, bcryptjs_1.hashSync)(newCode, salt);
            yield Promise.all([
                auth_1.UserRepo.updateVCode(email, hashedCode),
                (0, sendEmail_1.sendVerificationCode)({ email, code: newCode }),
            ]);
            throw new Error("Something wrong happened, please try again later");
        }
    });
}
