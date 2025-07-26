"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRoute = void 0;
const express_1 = require("express");
const auth_1 = require("../modules/auth");
const auth_2 = require("../middlewares/auth");
const authRoute = (0, express_1.Router)();
exports.authRoute = authRoute;
authRoute
    .post("/register", auth_1.register_handle)
    .put("/verify", auth_2.validate_session, auth_1.verify_handle) // Verify a user's email with a verification code (requires session)
    .post("/login", auth_1.login_handle)
    .post("/verify-login", auth_2.validate_login_session, auth_1.verify_login) // Verify login with additional security (e.g., 2FA code, requires login session)
    .put("/secure-login", auth_2.validate_session, auth_1.handle_secure_login) // Enable secure login (e.g., enable 2FA, requires session)
    .get("/profile", auth_2.validate_session, auth_1.profile_handle) // Get the current user's profile (requires session)
    .put("/profile", auth_2.validate_session, auth_1.update_profile) // Update the current user's profile "name and image" (requires session)
    .delete("/profile", auth_2.validate_session, auth_1.delete_profile)
    .get("/forget-password", auth_1.handle_get_verification_code) // Request a verification code for password reset (forget password)
    .put("/forget-password", auth_2.validate_rest_password_session, auth_1.handle_set_new_password) // Set a new password after verifying reset code (requires reset password session)
    .delete("/logout", auth_1.logout);
