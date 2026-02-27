import { Router } from "express";
import {
  register,
  verifyOTP,
  resendOTP,
  login,
  logout,
  forgotPassword,
  verifyResetOTP, // NEW: Step 2 verification
  resetPassword,
  getMe,
} from "../controllers/userAuthController.js";

import { protect } from "../middleware/authMiddleware.js";

const router = Router();

router.post("/register", register);
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);
router.post("/login", login);
router.post("/logout", logout);

// Password Reset Flow
router.post("/forgot-password", forgotPassword); // Step 1: Send OTP
router.post("/verify-reset-otp", verifyResetOTP); // Step 2: Validate OTP
router.post("/reset-password", resetPassword); // Step 3: Change Password

router.get("/me", protect, getMe);

export default router;
