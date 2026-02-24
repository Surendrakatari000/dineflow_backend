import { Router } from "express";

import {
  register,
  verifyOTP,
  resendOTP,
  login,
  logout,
} from "../controllers/userAuthController.js";

const router = Router();

router.post("/register", register);

router.post("/verify-otp", verifyOTP);

router.post("/resend-otp", resendOTP);

router.post("/login", login);

router.post("/logout", logout);

export default router;
