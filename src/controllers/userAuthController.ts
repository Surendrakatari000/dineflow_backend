import { Request, Response } from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { RowDataPacket, ResultSetHeader } from "mysql2";

import { pool } from "../config/db.js";
import { sendOTPEmail } from "../config/mailer.js";
import { generateToken } from "../utils/jwt.js";

/* INTERFACES */
interface UserRow extends RowDataPacket {
  id: number;
  name: string;
  email: string;
  password: string;
  mobile_no: string;
  is_verified: number;
}

interface OTPRow extends RowDataPacket {
  otp_hash: string;
  expires_at: Date;
}

/* UTILS */
const normalizeEmail = (email: string) => email.trim().toLowerCase();
const logError = (context: string, err: any) => {
  console.error(`[ERROR][${new Date().toISOString()}] ${context}:`, err);
};

/* GET ME (CHECK AUTH) */
export const getMe = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.id;
    console.log(`[GET-ME] Checking auth for UserID: ${userId}`);

    const [rows] = await pool.execute<RowDataPacket[]>(
      "SELECT id, name, email, mobile_no FROM users WHERE id = ?",
      [userId],
    );

    if (rows.length === 0) {
      console.log(`[GET-ME] User ${userId} not found in database.`);
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    console.log(`[GET-ME] Success! Found user: ${rows[0].email}`);
    res.status(200).json({ success: true, user: rows[0] });
  } catch (error: any) {
    logError("getMe", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
};

/* REGISTER */
export const register = async (req: Request, res: Response) => {
  console.log("[REGISTER] Process initiated...");
  const { name, password, mobile_no } = req.body;
  const email = normalizeEmail(req.body.email || "");

  const connection = await pool.getConnection();
  try {
    console.log(`[REGISTER] Validating email: ${email}`);
    await connection.beginTransaction();

    const [exist] = await connection.query<UserRow[]>(
      "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
      [email],
    );

    if (exist.length > 0) {
      console.log(
        `[REGISTER] Email ${email} already exists. Verified: ${exist[0].is_verified}`,
      );
      if (exist[0].is_verified === 0) {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message:
            "Email is already registered but not verified. Please go to the verify page.",
        });
      }
      await connection.rollback();
      return res
        .status(409)
        .json({ success: false, message: "Email already registered" });
    }

    console.log("[REGISTER] Hashing password and inserting user...");
    const hashed = await bcrypt.hash(password, 10);
    await connection.query<ResultSetHeader>(
      "INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)",
      [name, email, hashed, mobile_no],
    );

    const otp = crypto.randomInt(100000, 999999);
    const otpHash = await bcrypt.hash(String(otp), 10);

    console.log("[REGISTER] Storing OTP code...");
    await connection.query(
      "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
      [email],
    );
    await connection.query(
      "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
      [email, otpHash],
    );

    await connection.commit();
    console.log("[REGISTER] Committed. Sending email...");
    await sendOTPEmail(email, otp);

    res
      .status(201)
      .json({ success: true, message: "Registration successful. OTP sent" });
  } catch (err) {
    await connection.rollback();
    logError("Register", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    connection.release();
  }
};

/* VERIFY OTP (REGISTRATION) */
export const verifyOTP = async (req: Request, res: Response) => {
  console.log("[VERIFY-OTP] Verification attempt started...");
  const email = normalizeEmail(req.body.email || "");
  const { otp } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [userStatus] = await connection.query<UserRow[]>(
      "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
      [email],
    );

    if (userStatus.length > 0 && userStatus[0].is_verified === 1) {
      console.log("[VERIFY-OTP] User already verified.");
      const token = generateToken(userStatus[0].id);
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 604800000,
      });
      await connection.commit();
      return res
        .status(200)
        .json({
          success: true,
          message: "Account already verified",
          user: userStatus[0],
        });
    }

    const [rows] = await connection.query<OTPRow[]>(
      "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='register' AND expires_at > NOW() FOR UPDATE",
      [email],
    );

    if (
      rows.length === 0 ||
      !(await bcrypt.compare(String(otp), rows[0].otp_hash))
    ) {
      console.log("[VERIFY-OTP] Invalid/Expired OTP.");
      await connection.rollback();
      return res
        .status(401)
        .json({ success: false, message: "Incorrect or expired OTP" });
    }

    await connection.query("UPDATE users SET is_verified=1 WHERE email=?", [
      email,
    ]);
    await connection.query(
      "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
      [email],
    );
    await connection.commit();

    const token = generateToken(userStatus[0].id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 604800000,
    });

    console.log("[VERIFY-OTP] Verification Success.");
    res
      .status(200)
      .json({
        success: true,
        message: "Account verified successfully",
        user: userStatus[0],
      });
  } catch (err) {
    await connection.rollback();
    logError("VerifyOTP", err);
    res.status(500).json({ success: false, message: "Verification failed" });
  } finally {
    connection.release();
  }
};

/* LOGIN */
export const login = async (req: Request, res: Response) => {
  console.log("[LOGIN] Attempt started...");
  try {
    const email = normalizeEmail(req.body.email || "");
    const { password } = req.body;

    const [rows] = await pool.query<UserRow[]>(
      "SELECT * FROM users WHERE email=?",
      [email],
    );

    if (rows.length === 0) {
      console.log("[LOGIN] Email not registered.");
      return res
        .status(404)
        .json({ success: false, message: "Email is not registered" });
    }

    if (!(await bcrypt.compare(password, rows[0].password))) {
      console.log("[LOGIN] Invalid password.");
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (rows[0].is_verified === 0) {
      console.log("[LOGIN] User not verified.");
      return res
        .status(403)
        .json({
          success: false,
          message: "Please verify your account first",
          isVerified: false,
        });
    }

    const token = generateToken(rows[0].id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 604800000,
    });

    console.log("[LOGIN] Success.");
    return res
      .status(200)
      .json({ success: true, message: "Login successful", user: rows[0] });
  } catch (err) {
    logError("Login", err);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

/* FORGOT PASSWORD (STEP 1) */
export const forgotPassword = async (req: Request, res: Response) => {
  console.log("[FORGOT-PASSWORD] Password reset started...");
  const email = normalizeEmail(req.body.email || "");
  try {
    const [users] = await pool.query<UserRow[]>(
      "SELECT id FROM users WHERE email=?",
      [email],
    );

    // REQUIREMENT: Show explicitly if not registered
    if (users.length === 0) {
      console.log("[FORGOT-PASSWORD] Email not found.");
      return res
        .status(404)
        .json({ success: false, message: "Email is not registered" });
    }

    const otp = crypto.randomInt(100000, 999999);
    const otpHash = await bcrypt.hash(String(otp), 10);

    await pool.query(
      "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
      [email],
    );
    await pool.query(
      "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'reset_password', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
      [email, otpHash],
    );

    console.log("[FORGOT-PASSWORD] Sending OTP Email...");
    await sendOTPEmail(email, otp);
    res.status(200).json({ success: true, message: "OTP sent to your email" });
  } catch (err) {
    logError("ForgotPassword", err);
    res.status(500).json({ success: false, message: "Error initiating reset" });
  }
};

/* VERIFY RESET OTP (STEP 2) */
export const verifyResetOTP = async (req: Request, res: Response) => {
  console.log("[VERIFY-RESET-OTP] Checking OTP validity...");
  const email = normalizeEmail(req.body.email || "");
  const { otp } = req.body;

  try {
    const [rows] = await pool.query<OTPRow[]>(
      "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW()",
      [email],
    );

    if (
      rows.length === 0 ||
      !(await bcrypt.compare(String(otp), rows[0].otp_hash))
    ) {
      console.log("[VERIFY-RESET-OTP] Invalid or expired OTP.");
      return res
        .status(401)
        .json({ success: false, message: "Incorrect or expired OTP" });
    }

    console.log("[VERIFY-RESET-OTP] OTP Valid.");
    res
      .status(200)
      .json({ success: true, message: "OTP verified successfully" });
  } catch (err) {
    logError("VerifyResetOTP", err);
    res.status(500).json({ success: false, message: "Verification failed" });
  }
};

/* RESET PASSWORD (STEP 3) */
export const resetPassword = async (req: Request, res: Response) => {
  console.log("[RESET-PASSWORD] Finalizing update...");
  const email = normalizeEmail(req.body.email || "");
  const { otp, password: newPassword } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Fetch old password to compare
    const [users] = await connection.query<UserRow[]>(
      "SELECT password FROM users WHERE email=? FOR UPDATE",
      [email],
    );

    // REQUIREMENT: Check if new pass is different from old pass
    const isSamePassword = await bcrypt.compare(newPassword, users[0].password);
    if (isSamePassword) {
      console.log("[RESET-PASSWORD] New password matches old password.");
      await connection.rollback();
      return res
        .status(400)
        .json({
          success: false,
          message: "New password cannot be the same as your old password",
        });
    }

    // 2. Final OTP Verification
    const [rows] = await connection.query<OTPRow[]>(
      "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE",
      [email],
    );

    if (
      rows.length === 0 ||
      !(await bcrypt.compare(String(otp), rows[0].otp_hash))
    ) {
      console.log("[RESET-PASSWORD] OTP expired or incorrect at final step.");
      await connection.rollback();
      return res
        .status(401)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await connection.query("UPDATE users SET password=? WHERE email=?", [
      hashed,
      email,
    ]);
    await connection.query(
      "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
      [email],
    );

    await connection.commit();
    console.log("[RESET-PASSWORD] Password updated successfully.");
    res
      .status(200)
      .json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    await connection.rollback();
    logError("ResetPassword", err);
    res.status(500).json({ success: false, message: "Reset failed" });
  } finally {
    connection.release();
  }
};

/* RESEND OTP */
export const resendOTP = async (req: Request, res: Response) => {
  console.log("[RESEND-OTP] Generating new code...");
  const { purpose } = req.body;
  const email = normalizeEmail(req.body.email || "");
  try {
    const otp = crypto.randomInt(100000, 999999);
    const otpHash = await bcrypt.hash(String(otp), 10);

    await pool.query("DELETE FROM otp_codes WHERE email=? AND purpose=?", [
      email,
      purpose,
    ]);
    await pool.query(
      "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
      [email, purpose, otpHash],
    );

    await sendOTPEmail(email, otp);
    res.status(200).json({ success: true, message: "OTP resent successfully" });
  } catch (err) {
    logError("ResendOTP", err);
    res.status(500).json({ success: false, message: "Resend error" });
  }
};

/* LOGOUT */
export const logout = (req: Request, res: Response) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  res.status(200).json({ success: true, message: "Logged out" });
};

