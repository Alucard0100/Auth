import { Router } from "express";
import {
  delete_profile,
  login_handle,
  profile_handle,
  register_handle,
  verify_handle,
  handle_secure_login,
  update_profile,
  verify_login,
  handle_get_verification_code,
  handle_set_new_password,
  logout,
} from "../modules/auth";
import {
  validate_login_session,
  validate_session,
  validate_rest_password_session,
} from "../middlewares/auth";

const authRoute = Router();

authRoute
  .post("/register", register_handle)
  .put("/verify", validate_session, verify_handle) // Verify a user's email with a verification code (requires session)
  .post("/login", login_handle)
  .post("/verify-login", validate_login_session, verify_login) // Verify login with additional security (e.g., 2FA code, requires login session)
  .put("/secure-login", validate_session, handle_secure_login) // Enable secure login (e.g., enable 2FA, requires session)
  .get("/profile", validate_session, profile_handle) // Get the current user's profile (requires session)
  .put("/profile", validate_session, update_profile) // Update the current user's profile "name and image" (requires session)
  .delete("/profile", validate_session, delete_profile)
  .get("/forget-password", handle_get_verification_code) // Request a verification code for password reset (forget password)
  .put(
    "/forget-password",
    validate_rest_password_session,
    handle_set_new_password
  ) // Set a new password after verifying reset code (requires reset password session)
  .delete("/logout", logout);

export { authRoute };
