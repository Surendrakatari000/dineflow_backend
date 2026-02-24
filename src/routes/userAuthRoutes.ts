import { Router } from "express";
import {
  register,
  verifyOTP,
  resendOTP,
  login,
  logout,
  forgotPassword, // Added
  resetPassword, // Added
} from "../controllers/userAuthController.js";

const router = Router();

router.post("/register", register);
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);
router.post("/login", login);
router.post("/logout", logout);
router.post("/forgot-password", forgotPassword); // New Route
router.post("/reset-password", resetPassword); // New Route

export default router;
