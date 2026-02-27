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

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import crypto from "crypto";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// /* INTERFACES */
// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// interface OTPRow extends RowDataPacket {
//   otp_hash: string;
//   expires_at: Date;
// }

// /* UTILS */
// const normalizeEmail = (email: string) => email.trim().toLowerCase();
// const logError = (context: string, err: any) => {
//   console.error(`[ERROR][${new Date().toISOString()}] ${context}:`, err);
// };

// /* GET ME (CHECK AUTH) */
// export const getMe = async (req: Request, res: Response) => {
//   try {
//     const userId = (req as any).user.id;
//     console.log(`[GET-ME] Checking auth for UserID: ${userId}`);

//     const [rows] = await pool.execute<RowDataPacket[]>(
//       "SELECT id, name, email, mobile_no FROM users WHERE id = ?",
//       [userId],
//     );

//     if (rows.length === 0) {
//       console.log(`[GET-ME] User ${userId} not found in database.`);
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found" });
//     }

//     console.log(`[GET-ME] Success! Found user: ${rows[0].email}`);
//     res.status(200).json({ success: true, user: rows[0] });
//   } catch (error: any) {
//     logError("getMe", error);
//     res.status(500).json({ success: false, message: "Server Error" });
//   }
// };

// /* REGISTER */
// export const register = async (req: Request, res: Response) => {
//   console.log("[REGISTER] Process initiated...");
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   const connection = await pool.getConnection();
//   try {
//     console.log(`[REGISTER] Validating email: ${email}`);
//     await connection.beginTransaction();

//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (exist.length > 0) {
//       console.log(
//         `[REGISTER] Email ${email} already exists. Verified status: ${exist[0].is_verified}`,
//       );
//       if (exist[0].is_verified === 0) {
//         await connection.rollback();
//         return res
//           .status(400)
//           .json({
//             success: false,
//             message:
//               "Email is already registered but not verified. Please go to the verify page.",
//           });
//       }
//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     console.log("[REGISTER] Hashing password and inserting user...");
//     const hashed = await bcrypt.hash(password, 10);
//     await connection.query<ResultSetHeader>(
//       "INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)",
//       [name, email, hashed, mobile_no],
//     );

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     console.log("[REGISTER] Cleaning old OTPs and storing new code...");
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
//       [email],
//     );
//     await connection.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, otpHash],
//     );

//     await connection.commit();
//     console.log("[REGISTER] Transaction committed. Sending email...");
//     await sendOTPEmail(email, otp);
//     console.log("[REGISTER] Registration successful. OTP sent.");

//     res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     logError("Register", err);
//     res.status(500).json({ success: false, message: "Internal server error" });
//   } finally {
//     connection.release();
//   }
// };

// /* VERIFY OTP */
// export const verifyOTP = async (req: Request, res: Response) => {
//   console.log("[VERIFY-OTP] Verification attempt started...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp } = req.body;

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     console.log(`[VERIFY-OTP] Checking status for: ${email}`);

//     const [userStatus] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (userStatus.length > 0 && userStatus[0].is_verified === 1) {
//       console.log(
//         "[VERIFY-OTP] User already verified. Handling race condition.",
//       );
//       const token = generateToken(userStatus[0].id);
//       res.cookie("token", token, {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === "production",
//         sameSite: "strict",
//         maxAge: 7 * 24 * 60 * 60 * 1000,
//       });
//       await connection.commit();

//       const [user] = await pool.execute<RowDataPacket[]>(
//         "SELECT id, name, email, mobile_no FROM users WHERE email = ?",
//         [email],
//       );
//       return res
//         .status(200)
//         .json({
//           success: true,
//           message: "Account verified successfully",
//           user: user[0],
//         });
//     }

//     console.log("[VERIFY-OTP] Fetching OTP from DB...");
//     const [rows] = await connection.query<OTPRow[]>(
//       "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='register' AND expires_at > NOW() FOR UPDATE",
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[VERIFY-OTP] No valid/unexpired OTP found.");
//       await connection.rollback();
//       return res
//         .status(410)
//         .json({ success: false, message: "OTP expired or not found" });
//     }

//     console.log("[VERIFY-OTP] Comparing hashes...");
//     if (!(await bcrypt.compare(String(otp), rows[0].otp_hash))) {
//       console.log("[VERIFY-OTP] Hash mismatch! Incorrect code.");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Incorrect OTP" });
//     }

//     console.log("[VERIFY-OTP] OTP valid. Updating user to verified.");
//     await connection.query("UPDATE users SET is_verified=1 WHERE email=?", [
//       email,
//     ]);
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
//       [email],
//     );
//     await connection.commit();

//     console.log("[VERIFY-OTP] Fetching final user data for frontend...");
//     const [updatedUser] = await pool.execute<RowDataPacket[]>(
//       "SELECT id, name, email, mobile_no FROM users WHERE email = ?",
//       [email],
//     );

//     const token = generateToken(userStatus[0].id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     console.log("[VERIFY-OTP] Success! User authenticated.");
//     res
//       .status(200)
//       .json({
//         success: true,
//         message: "Account verified successfully",
//         user: updatedUser[0],
//       });
//   } catch (err) {
//     await connection.rollback();
//     logError("VerifyOTP", err);
//     res.status(500).json({ success: false, message: "Verification failed" });
//   } finally {
//     connection.release();
//   }
// };

// /* LOGIN */
// export const login = async (req: Request, res: Response) => {
//   console.log("[LOGIN] 1. Login attempt started...");
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const { password } = req.body;

//     console.log(`[LOGIN] 2. Searching for email: ${email}`);
//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );

//     // Check if user exists
//     if (rows.length === 0) {
//       console.log("[LOGIN] 2a. Fail: Email not registered.");
//       return res
//         .status(404)
//         .json({ success: false, message: "Email is not registered" });
//     }

//     // Verify Password
//     console.log("[LOGIN] 3. Verifying password...");
//     const isMatch = await bcrypt.compare(password, rows[0].password);
//     if (!isMatch) {
//       console.log("[LOGIN] 3a. Fail: Password mismatch.");
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid credentials" });
//     }

//     // Check Verification Status
//     console.log(`[LOGIN] 4. Checking verification status for user ID: ${rows[0].id}`);
//     if (rows[0].is_verified === 0) {
//       console.log("[LOGIN] 4a. Redirect Trigger: User exists but is not verified.");
//       return res.status(403).json({
//         success: false,
//         message: "Please verify your account first",
//         isVerified: false // Flag for frontend logic
//       });
//     }

//     // Generate Token
//     console.log("[LOGIN] 5. Authentication successful. Generating token...");
//     const token = generateToken(rows[0].id);

//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     console.log("[LOGIN] 6. Login successful. Token set in cookie.");
//     return res.status(200).json({
//       success: true,
//       message: "Login successful",
//       user: { id: rows[0].id, email: rows[0].email, name: rows[0].name }
//     });

//   } catch (err) {
//     console.error("[LOGIN] CRITICAL ERROR:", err);
//     logError("Login", err);
//     return res.status(500).json({ success: false, message: "Internal server error during login" });
//   }
// };

// /* FORGOT & RESET PASSWORD */
// export const forgotPassword = async (req: Request, res: Response) => {
//   console.log("[FORGOT-PASSWORD] Password reset initiated...");
//   const email = normalizeEmail(req.body.email || "");
//   try {
//     const [users] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );
//     if (users.length === 0) {
//       console.log(
//         "[FORGOT-PASSWORD] Email not found. Sending generic success.",
//       );
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, OTP sent" });
//     }

//     console.log("[FORGOT-PASSWORD] Generating reset OTP...");
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await pool.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
//       [email],
//     );
//     await pool.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'reset_password', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     console.log("[FORGOT-PASSWORD] OTP sent successfully.");
//     res.status(200).json({ success: true, message: "OTP sent to your email" });
//   } catch (err) {
//     logError("ForgotPassword", err);
//     res.status(500).json({ success: false, message: "Error initiating reset" });
//   }
// };

// /* RESEND OTP & LOGOUT */
// export const resendOTP = async (req: Request, res: Response) => {
//   console.log("[RESEND-OTP] Request received.");
//   const { purpose } = req.body;
//   const email = normalizeEmail(req.body.email || "");
//   try {
//     console.log(`[RESEND-OTP] Generating new ${purpose} OTP for ${email}`);
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await pool.query("DELETE FROM otp_codes WHERE email=? AND purpose=?", [
//       email,
//       purpose,
//     ]);
//     await pool.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, purpose, otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     console.log("[RESEND-OTP] Success.");
//     res.status(200).json({ success: true, message: "OTP resent successfully" });
//   } catch (err) {
//     logError("ResendOTP", err);
//     res.status(500).json({ success: false, message: "Resend error" });
//   }
// };

// export const logout = (req: Request, res: Response) => {
//   console.log("[LOGOUT] Clearing token cookie.");
//   res.clearCookie("token", {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "strict",
//   });
//   res.status(200).json({ success: true, message: "Logged out" });
// };

// /* RESET-PASSWORD CONTROLLER */
// export const resetPassword = async (req: Request, res: Response) => {
//   console.log("[RESET-PASSWORD] 1. Password reset process started...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     console.log(`[RESET-PASSWORD] 2. Verifying OTP for: ${email}`);

//     // Fetch and Lock the OTP record
//     const [rows] = await connection.query<OTPRow[]>(
//       "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE",
//       [email],
//     );

//     // Verify OTP exists and matches
//     if (
//       rows.length === 0 ||
//       !(await bcrypt.compare(String(otp), rows[0].otp_hash))
//     ) {
//       console.log("[RESET-PASSWORD] 2a. Fail: Invalid or expired OTP.");
//       await connection.rollback();
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid or expired OTP" });
//     }

//     // Hash the new password
//     console.log("[RESET-PASSWORD] 3. OTP verified. Hashing new password...");
//     const hashed = await bcrypt.hash(newPassword, 10);

//     // Update the user's password first
//     console.log("[RESET-PASSWORD] 4. Updating user password in database...");
//     const [updateResult] = await connection.query<ResultSetHeader>(
//       "UPDATE users SET password=? WHERE email=?",
//       [hashed, email]
//     );

//     if (updateResult.affectedRows === 0) {
//       throw new Error("User record not found during password update");
//     }

//     // Delete the OTP only after the password has been successfully updated
//     console.log("[RESET-PASSWORD] 5. Password updated. Cleaning up used OTP...");
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
//       [email],
//     );

//     await connection.commit();
//     console.log("[RESET-PASSWORD] 6. Success! Reset complete.");

//     return res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });

//   } catch (err) {
//     await connection.rollback();
//     logError("ResetPassword", err);
//     return res.status(500).json({ success: false, message: "Reset failed. Please try again." });
//   } finally {
//     connection.release();
//   }
// };

// export const resetPassword = async (req: Request, res: Response) => {
//   console.log("[RESET-PASSWORD] Updating password...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;
//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     console.log(`[RESET-PASSWORD] Verifying OTP for ${email}`);

//     const [rows] = await connection.query<OTPRow[]>(
//       "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE",
//       [email],
//     );

//     if (
//       rows.length === 0 ||
//       !(await bcrypt.compare(String(otp), rows[0].otp_hash))
//     ) {
//       console.log("[RESET-PASSWORD] Invalid or expired OTP.");
//       await connection.rollback();
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid or expired OTP" });
//     }

//     console.log("[RESET-PASSWORD] Hashing new password...");
//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query("UPDATE users SET password=? WHERE email=?", [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
//       [email],
//     );

//     await connection.commit();
//     console.log("[RESET-PASSWORD] Success! Password updated.");
//     res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("ResetPassword", err);
//     res.status(500).json({ success: false, message: "Reset failed" });
//   } finally {
//     connection.release();
//   }
// };

//  export const login = async (req: Request, res: Response) => {
//    console.log("[LOGIN] Login attempt started...");
//    try {
//      const email = normalizeEmail(req.body.email || "");
//      const { password } = req.body;

//      console.log(`[LOGIN] Searching for email: ${email}`);
//      const [rows] = await pool.query<UserRow[]>(
//        "SELECT * FROM users WHERE email=?",
//        [email],
//      );

//      if (rows.length === 0) {
//        console.log("[LOGIN] Email not registered.");
//        return res
//          .status(404)
//          .json({ success: false, message: "Email is not registered" });
//      }

//      console.log("[LOGIN] Verifying password...");
//      if (!(await bcrypt.compare(password, rows[0].password))) {
//        console.log("[LOGIN] Password mismatch.");
//        return res
//          .status(401)
//          .json({ success: false, message: "Invalid credentials" });
//      }

//      if (rows[0].is_verified === 0) {
//        console.log("[LOGIN] User exists but is not verified.");
//        return res
//          .status(403)
//          .json({ success: false, message: "Please verify your account first" });
//      }

//      console.log("[LOGIN] Authentication successful. Generating token...");
//      const token = generateToken(rows[0].id);
//      res.cookie("token", token, {
//        httpOnly: true,
//        secure: process.env.NODE_ENV === "production",
//        sameSite: "strict",
//        maxAge: 7 * 24 * 60 * 60 * 1000,
//      });

//      res
//        .status(200)
//        .json({ success: true, message: "Login successful", user: rows[0] });
//      console.log("[LOGIN] Login successful. Token set in cookie.");
//    } catch (err) {
//      logError("Login", err);
//      res.status(500).json({ success: false, message: "Login error" });
//    }
//  };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import crypto from "crypto";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// /*
// INTERFACES
// */
// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// interface OTPRow extends RowDataPacket {
//   otp_hash: string;
//   expires_at: Date;
// }

// /*
// UTILS
// */
// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const normalizeEmail = (email: string) => email.trim().toLowerCase();

// const logError = (context: string, err: any) => {
//   console.error(`[ERROR][${new Date().toISOString()}] ${context}:`, err);
// };

// /*
// GET ME (CHECK AUTH)
// */
// export const getMe = async (req: Request, res: Response) => {
//   try {
//     const userId = (req as any).user.id;
//     console.log(`[GET-ME] Checking auth for UserID: ${userId}`);

//     const [rows] = await pool.execute<RowDataPacket[]>(
//       "SELECT id, name, email, mobile_no FROM users WHERE id = ?",
//       [userId],
//     );

//     if (rows.length === 0) {
//       console.log(`[GET-ME] User not found in DB.`);
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found" });
//     }

//     console.log(`[GET-ME] Success: ${rows[0].email}`);
//     res.status(200).json({ success: true, user: rows[0] });
//   } catch (error: any) {
//     logError("getMe", error);
//     res.status(500).json({ success: false, message: "Server Error" });
//   }
// };

// /*
// REGISTER
// */
// export const register = async (req: Request, res: Response) => {
//   console.log("[REGISTER] Starting...");
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!name || !email || !password || !mobile_no) {
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (exist.length > 0) {
//       if (exist[0].is_verified === 0) {
//         console.log("[REGISTER] Unverified user found. Redirecting to OTP.");
//         await connection.rollback();
//         return res.status(400).json({
//           success: false,
//           message:
//             "Email is already registered but not verified. Please go to the verify page.",
//         });
//       }
//       console.log("[REGISTER] Verified user found. Blocking.");
//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     const hashed = await bcrypt.hash(password, 10);
//     await connection.query<ResultSetHeader>(
//       "INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)",
//       [name, email, hashed, mobile_no],
//     );

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
//       [email],
//     );
//     await connection.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);
//     console.log("[REGISTER] Success. OTP sent.");
//     res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     logError("Register", err);
//     res.status(500).json({ success: false, message: "Internal server error" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// VERIFY OTP
// */
// export const verifyOTP = async (req: Request, res: Response) => {
//   console.log("[VERIFY-OTP] Starting...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp } = req.body;

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     // Race condition check: Is user already verified?
//     const [userStatus] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (userStatus.length > 0 && userStatus[0].is_verified === 1) {
//       console.log(
//         "[VERIFY-OTP] User already verified (Race condition handled).",
//       );
//       const token = generateToken(userStatus[0].id);
//       res.cookie("token", token, {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === "production",
//         sameSite: "strict",
//         maxAge: 7 * 24 * 60 * 60 * 1000,
//       });
//       await connection.commit();
//       return res
//         .status(200)
//         .json({ success: true, message: "Account verified successfully" });
//     }

//     const [rows] = await connection.query<OTPRow[]>(
//       "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='register' AND expires_at > NOW() FOR UPDATE",
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[VERIFY-OTP] No valid OTP found.");
//       await connection.rollback();
//       return res
//         .status(410)
//         .json({ success: false, message: "OTP expired or not found" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       console.log("[VERIFY-OTP] Hash mismatch.");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Incorrect OTP" });
//     }

//     await connection.query("UPDATE users SET is_verified=1 WHERE email=?", [
//       email,
//     ]);
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='register'",
//       [email],
//     );

//     await connection.commit();
//     const token = generateToken(userStatus[0].id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });
//     console.log("[VERIFY-OTP] Success.");
//     res
//       .status(200)
//       .json({ success: true, message: "Account verified successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("VerifyOTP", err);
//     res.status(500).json({ success: false, message: "Verification failed" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGIN
// */
// export const login = async (req: Request, res: Response) => {
//   console.log("[LOGIN] Attempting...");
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const { password } = req.body;

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );
//     if (rows.length === 0) {
//       console.log("[LOGIN] Email not found.");
//       return res
//         .status(404)
//         .json({ success: false, message: "Email is not registered" });
//     }

//     const user = rows[0];
//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid)
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid credentials" });

//     if (user.is_verified === 0)
//       return res
//         .status(403)
//         .json({ success: false, message: "Please verify your account first" });

//     const token = generateToken(user.id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });
//     console.log("[LOGIN] Success.");
//     res.status(200).json({ success: true, message: "Login successful" });
//   } catch (err) {
//     logError("Login", err);
//     res.status(500).json({ success: false, message: "Login error" });
//   }
// };

// /*
// FORGOT PASSWORD
// */
// export const forgotPassword = async (req: Request, res: Response) => {
//   console.log("[FORGOT-PASSWORD] Initializing...");
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     console.log(`[FORGOT-PASSWORD] Target: ${email}`);

//     const [users] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     if (users.length === 0) {
//       console.log(
//         "[FORGOT-PASSWORD] Email not in DB. Sending generic success.",
//       );
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, OTP sent" });
//     }

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     console.log("[FORGOT-PASSWORD] Storing reset OTP...");
//     await pool.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
//       [email],
//     );
//     await pool.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'reset_password', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     console.log("[FORGOT-PASSWORD] Email sent.");
//     res.status(200).json({ success: true, message: "OTP sent to your email" });
//   } catch (err) {
//     logError("ForgotPassword", err);
//     res.status(500).json({ success: false, message: "Error initiating reset" });
//   }
// };

// /*
// RESET PASSWORD
// */
// export const resetPassword = async (req: Request, res: Response) => {
//   console.log("[RESET-PASSWORD] Starting update...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     const [rows] = await connection.query<OTPRow[]>(
//       "SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE",
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[RESET-PASSWORD] OTP expired/invalid.");
//       await connection.rollback();
//       return res.status(410).json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       console.log("[RESET-PASSWORD] OTP hash mismatch.");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Invalid OTP" });
//     }

//     // Check if same as old password
//     const [userRows] = await connection.query<UserRow[]>(
//       "SELECT password FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (userRows.length > 0) {
//       const isSame = await bcrypt.compare(newPassword, userRows[0].password);
//       if (isSame) {
//         console.log("[RESET-PASSWORD] New password matches old password.");
//         await connection.rollback();
//         return res
//           .status(400)
//           .json({
//             success: false,
//             message: "New password cannot be the same as old one",
//           });
//       }
//     }

//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query("UPDATE users SET password=? WHERE email=?", [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'",
//       [email],
//     );

//     await connection.commit();
//     console.log("[RESET-PASSWORD] Success.");
//     res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("ResetPassword", err);
//     res.status(500).json({ success: false, message: "Reset failed" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// RESEND OTP
// */
// export const resendOTP = async (req: Request, res: Response) => {
//   console.log("[RESEND-OTP] Initializing...");
//   const { purpose } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();
//     const [user] = await connection.query<UserRow[]>(
//       "SELECT is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (user.length === 0) {
//       await connection.rollback();
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, new OTP sent" });
//     }

//     const [existingOTP] = await connection.query<RowDataPacket[]>(
//       "SELECT created_at FROM otp_codes WHERE email=? AND purpose=? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
//       [email, purpose],
//     );
//     if (existingOTP.length > 0) {
//       await connection.rollback();
//       return res
//         .status(429)
//         .json({ success: false, message: "Wait 1 minute before resending" });
//     }

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose=?",
//       [email, purpose],
//     );
//     await connection.query(
//       "INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
//       [email, purpose, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);
//     console.log("[RESEND-OTP] Success.");
//     res.status(200).json({ success: true, message: "OTP resent successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("ResendOTP", err);
//     res.status(500).json({ success: false, message: "Resend error" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGOUT
// */
// export const logout = (req: Request, res: Response) => {
//   console.log("[LOGOUT] Clearing cookie.");
//   res.clearCookie("token", {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "strict",
//   });
//   res.status(200).json({ success: true, message: "Logged out" });
// };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import crypto from "crypto";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// // export const getMe = async (req: Request, res: Response) => {
// //   try {
// //     // 1. Get the user ID attached by your authMiddleware
// //     const userId = (req as any).user.id;

// //     // 2. Fetch user details from MySQL (excluding password for security)
// //     // We use RowDataPacket[] to tell TypeScript what the database returns
// //     const [rows] = await pool.execute<RowDataPacket[]>(
// //       "SELECT id, name, email, mobile_no, FROM users WHERE id = ?",
// //       [userId],
// //     );

// //     // 3. Check if user exists
// //     if (rows.length === 0) {
// //       return res.status(404).json({
// //         success: false,
// //         message: "User not found",
// //       });
// //     }

// //     // 4. Return user data to the frontend
// //     res.status(200).json({
// //       success: true,
// //       user: rows[0],
// //     });
// //   } catch (error: any) {
// //     console.error("Error in getMe:", error.message);
// //     res.status(500).json({
// //       success: false,
// //       message: "Server Error while fetching user data",
// //     });
// //   }
// // };

// /*
// GET CURRENT USER (CHECK AUTH)
// */

// /*
// INTERFACES
// */
// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// interface OTPRow extends RowDataPacket {
//   otp_hash: string;
//   expires_at: Date;
// }

// /*
// REGEX & UTILS
// */
// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
// const mobileRegex = /^[0-9]{10}$/;

// const normalizeEmail = (email: string) => email.trim().toLowerCase();

// const logError = (context: string, err: any) => {
//   console.error(`[ERROR][${new Date().toISOString()}] ${context}:`, err);
// };

// export const getMe = async (req: Request, res: Response) => {
//   try {
//     // 1. Get the user ID attached by your authMiddleware
//     // Ensure your authMiddleware sets req.user.id
//     const userId = (req as any).user.id;

//     // 2. Fetch user details from MySQL (excluding password for security)
//     // FIX: Removed the trailing comma after mobile_no
//     const [rows] = await pool.execute<RowDataPacket[]>(
//       "SELECT id, name, email, mobile_no FROM users WHERE id = ?",
//       [userId],
//     );

//     // 3. Check if user exists
//     if (rows.length === 0) {
//       console.log(`[GET-ME] User with ID ${userId} not found.`);
//       return res.status(404).json({
//         success: false,
//         message: "User not found",
//       });
//     }

//     // 4. Return user data to the frontend
//     console.log(`[GET-ME] User found: ${rows[0].email}`);
//     res.status(200).json({
//       success: true,
//       user: rows[0],
//     });
//   } catch (error: any) {
//     logError("getMe", error);
//     res.status(500).json({
//       success: false,
//       message: "Server Error while fetching user data",
//     });
//   }
// };

// export const register = async (req: Request, res: Response) => {
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!name || !email || !password || !mobile_no) {
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (exist.length > 0) {
//       const existingUser = exist[0];

//       // If user exists but is NOT verified
//       if (existingUser.is_verified === 0) {
//         await connection.rollback();
//         // Return 400 so Redux triggers the 'rejected' case with this message
//         return res.status(400).json({
//           success: false,
//           message:
//             "Email is already registered but not verified. Please go to the verify page.",
//         });
//       }

//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     const hashed = await bcrypt.hash(password, 10);
//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     return res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     logError("Register", err);
//     return res
//       .status(500)
//       .json({ success: false, message: "Internal server error" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// VERIFY OTP
// */
// export const verifyOTP = async (req: Request, res: Response) => {
//   console.log("[VERIFY-OTP] Starting verification...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp } = req.body;

//   if (!otp || String(otp).length !== 6) {
//     console.log("[VERIFY-OTP] Validation failed: Invalid OTP length");
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid OTP length" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     console.log("[VERIFY-OTP] Connection acquired. Starting transaction...");
//     await connection.beginTransaction();

//     console.log("[VERIFY-OTP] Fetching OTP from database...");
//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='register' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[VERIFY-OTP] No valid/unexpired OTP found. Rolling back...");
//       await connection.rollback();
//       return res
//         .status(410)
//         .json({ success: false, message: "OTP expired or not found" });
//     }

//     console.log("[VERIFY-OTP] Comparing OTP hash...");
//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       console.log("[VERIFY-OTP] OTP mismatch. Rolling back...");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Incorrect OTP" });
//     }

//     console.log(
//       "[VERIFY-OTP] OTP valid. Updating user status and deleting code...",
//     );
//     await connection.query(`UPDATE users SET is_verified=1 WHERE email=?`, [
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );

//     const [userRows] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     console.log("[VERIFY-OTP] Committing transaction...");
//     await connection.commit();

//     console.log("[VERIFY-OTP] Generating JWT and setting cookie...");
//     const token = generateToken(userRows[0].id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     console.log("[VERIFY-OTP] Verification success.");
//     res
//       .status(200)
//       .json({ success: true, message: "Account verified successfully" });
//   } catch (err) {
//     console.log("[VERIFY-OTP] Catch block triggered. Rolling back...");
//     await connection.rollback();
//     logError("VerifyOTP", err);
//     res.status(500).json({
//       success: false,
//       message: `Verification failed: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   } finally {
//     connection.release();
//     console.log("[VERIFY-OTP] Connection released.");
//   }
// };

// /*
// LOGIN
// */
// export const login = async (req: Request, res: Response) => {
//   console.log("[LOGIN] Starting login attempt...");
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const { password } = req.body;

//     console.log(`[LOGIN] email=${email}`);

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );
//     // if (rows.length === 0) {
//     //   console.log("[LOGIN] User not found.");
//     //   return res
//     //     .status(401)
//     //     .json({ success: false, message: "Invalid credentials" });
//     // }
//     if (rows.length === 0) {
//       console.log("[LOGIN] User not found.");
//       return res
//         .status(404) // Using 404 is more accurate for "Not Found"
//         .json({ success: false, message: "Email is not registered" });
//     }

//     const user = rows[0];
//     console.log("[LOGIN] Comparing password...");
//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid) {
//       console.log("[LOGIN] Password mismatch.");
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid credentials" });
//     }

//     if (user.is_verified === 0) {
//       console.log("[LOGIN] Account not verified.");
//       return res
//         .status(403)
//         .json({ success: false, message: "Please verify your account first" });
//     }

//     console.log("[LOGIN] Generating token...");
//     const token = generateToken(user.id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     console.log("[LOGIN] Login success.");
//     res.status(200).json({ success: true, message: "Login successful" });
//   } catch (err) {
//     logError("Login", err);
//     res.status(500).json({
//       success: false,
//       message: `Login error: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   }
// };

// /*
// FORGOT PASSWORD
// */
// export const forgotPassword = async (req: Request, res: Response) => {
//   console.log("[FORGOT-PASSWORD] Initializing...");
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     console.log(`[FORGOT-PASSWORD] email=${email}`);

//     const [users] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     if (users.length === 0) {
//       console.log(
//         "[FORGOT-PASSWORD] User not found. Sending generic success response for security.",
//       );
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, OTP sent" });
//     }

//     console.log("[FORGOT-PASSWORD] Generating OTP...");
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     console.log("[FORGOT-PASSWORD] Storing reset OTP...");
//     await pool.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'`,
//       [email],
//     );
//     await pool.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'reset_password', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     console.log("[FORGOT-PASSWORD] Success.");
//     res
//       .status(200)
//       .json({ success: true, message: "If account exists, OTP sent" });
//   } catch (err) {
//     logError("ForgotPassword", err);
//     res.status(500).json({
//       success: false,
//       message: `Error: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   }
// };

// /*
// RESET PASSWORD
// */
// export const resetPassword = async (req: Request, res: Response) => {
//   console.log("[RESET-PASSWORD] Starting...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   if (String(otp).length !== 6) {
//     console.log("[RESET-PASSWORD] Validation failed: OTP length");
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid OTP format" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     console.log("[RESET-PASSWORD] Starting transaction...");
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[RESET-PASSWORD] OTP expired/invalid. Rolling back...");
//       await connection.rollback();
//       return res.status(410).json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       console.log("[RESET-PASSWORD] OTP mismatch. Rolling back...");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Invalid OTP" });
//     }

//     // --- NEW: OLD PASSWORD DETECTION START ---
//     console.log(
//       "[RESET-PASSWORD] Checking if new password matches old password...",
//     );
//     const [userRows] = await connection.query<UserRow[]>(
//       "SELECT password FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (userRows.length > 0) {
//       const isSamePassword = await bcrypt.compare(
//         newPassword,
//         userRows[0].password,
//       );
//       if (isSamePassword) {
//         console.log("[RESET-PASSWORD] Same password detected. Rolling back...");
//         await connection.rollback();
//         return res.status(400).json({
//           success: false,
//           message: "New password cannot be the same as your current password",
//         });
//       }
//     }
//     // --- NEW: OLD PASSWORD DETECTION END ---

//     console.log("[RESET-PASSWORD] Hashing new password and updating user...");
//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query(`UPDATE users SET password=? WHERE email=?`, [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'`,
//       [email],
//     );

//     console.log("[RESET-PASSWORD] Committing...");
//     await connection.commit();
//     res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });
//   } catch (err) {
//     console.log("[RESET-PASSWORD] Catch block triggered.");
//     await connection.rollback();
//     logError("ResetPassword", err);
//     res.status(500).json({
//       success: false,
//       message: `Reset failed: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   } finally {
//     connection.release();
//     console.log("[RESET-PASSWORD] Connection released.");
//   }
// };
// /*
// RESEND OTP
// */
// export const resendOTP = async (req: Request, res: Response) => {
//   console.log("[RESEND-OTP] Initializing...");
//   const { purpose } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   const connection = await pool.getConnection();
//   try {
//     console.log("[RESEND-OTP] Checking user and verification status...");
//     await connection.beginTransaction();

//     const [user] = await connection.query<UserRow[]>(
//       "SELECT is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (user.length === 0) {
//       console.log("[RESEND-OTP] User not found. Rolling back.");
//       await connection.rollback();
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, new OTP sent" });
//     }

//     if (purpose === "register" && user[0].is_verified === 1) {
//       console.log("[RESEND-OTP] User already verified. Rolling back.");
//       await connection.rollback();
//       return res
//         .status(400)
//         .json({ success: false, message: "Account already verified" });
//     }

//     console.log("[RESEND-OTP] Checking rate limit...");
//     const [existingOTP] = await connection.query<RowDataPacket[]>(
//       "SELECT created_at FROM otp_codes WHERE email=? AND purpose=? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
//       [email, purpose],
//     );

//     if (existingOTP.length > 0) {
//       console.log("[RESEND-OTP] Rate limit hit. Rolling back.");
//       await connection.rollback();
//       return res
//         .status(429)
//         .json({ success: false, message: "Wait 1 minute before resending" });
//     }

//     console.log("[RESEND-OTP] Generating new OTP...");
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose=?",
//       [email, purpose],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, purpose, otpHash],
//     );

//     console.log("[RESEND-OTP] Committing and sending email...");
//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res.status(200).json({ success: true, message: "OTP resent successfully" });
//   } catch (err) {
//     console.log("[RESEND-OTP] Catch block triggered.");
//     await connection.rollback();
//     logError("ResendOTP", err);
//     res.status(500).json({
//       success: false,
//       message: `Resend error: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   } finally {
//     connection.release();
//     console.log("[RESEND-OTP] Connection released.");
//   }
// };

// /*
// LOGOUT
// */
// export const logout = (req: Request, res: Response) => {
//   console.log("[LOGOUT] Clearing token cookie...");
//   res.clearCookie("token", {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "strict",
//   });
//   console.log("[LOGOUT] Success.");
//   res.status(200).json({ success: true, message: "Logged out" });
// };

/*
REGISTER
*/
// export const register = async (req: Request, res: Response) => {
//   console.log("[REGISTER] Starting registration process...");
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   console.log(`[REGISTER] Input received: email=${email}, name=${name}`);

//   if (!name || !email || !password || !mobile_no) {
//     console.log("[REGISTER] Validation failed: Missing fields");
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   if (!emailRegex.test(email)) {
//     console.log("[REGISTER] Validation failed: Invalid email format");
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid email format" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     console.log(
//       "[REGISTER] Database connection acquired. Starting transaction...",
//     );
//     await connection.beginTransaction();

//     console.log("[REGISTER] Checking if email exists...");
//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (exist.length > 0) {
//       console.log("[REGISTER] Email already exists. Rolling back...");
//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     console.log("[REGISTER] Hashing password...");
//     const hashed = await bcrypt.hash(password, 10);

//     console.log("[REGISTER] Inserting new user...");
//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     console.log("[REGISTER] Generating secure OTP...");
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     console.log("[REGISTER] Cleaning old OTPs and inserting new one...");
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     console.log("[REGISTER] Committing transaction...");
//     await connection.commit();

//     console.log("[REGISTER] Attempting to send OTP email...");
//     await sendOTPEmail(email, otp);

//     console.log("[REGISTER] Success. Response sent.");
//     res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     console.log("[REGISTER] Catch block triggered. Rolling back...");
//     await connection.rollback();
//     logError("Register", err);
//     res.status(500).json({
//       success: false,
//       message: `Register error: ${err instanceof Error ? err.message : String(err)}`,
//     });
//   } finally {
//     connection.release();
//     console.log("[REGISTER] Connection released.");
//   }
// };
// export const register = async (req: Request, res: Response) => {
//   console.log("[REGISTER] Starting registration process...");
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!name || !email || !password || !mobile_no) {
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   if (!emailRegex.test(email)) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid email format" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     console.log("[REGISTER] Checking if email exists...");
//     // We select is_verified to check if we should let them go to the verify page
//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id, is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (exist.length > 0) {
//       const existingUser = exist[0];

//       // Handle the case where they registered but never verified their email
//       if (existingUser.is_verified === 0) {
//         console.log("[REGISTER] User exists but not verified.");
//         await connection.rollback();
//         return res.status(200).json({
//           success: false,
//           message:
//             "Email is already registered but not verified. Please go to the verify page.",
//         });
//       }

//       console.log("[REGISTER] Email already exists and is verified.");
//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     const hashed = await bcrypt.hash(password, 10);

//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     logError("Register", err);
//     res
//       .status(500)
//       .json({
//         success: false,
//         message: "Internal server error during registration",
//       });
//   } finally {
//     connection.release();
//   }
// };

/*
RESET PASSWORD
*/
// export const resetPassword = async (req: Request, res: Response) => {
//   console.log("[RESET-PASSWORD] Starting...");
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   if (String(otp).length !== 6) {
//     console.log("[RESET-PASSWORD] Validation failed: OTP length");
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid OTP format" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     console.log("[RESET-PASSWORD] Starting transaction...");
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       console.log("[RESET-PASSWORD] OTP expired/invalid. Rolling back...");
//       await connection.rollback();
//       return res.status(410).json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       console.log("[RESET-PASSWORD] OTP mismatch. Rolling back...");
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Invalid OTP" });
//     }

//     console.log("[RESET-PASSWORD] Hashing new password and updating user...");
//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query(`UPDATE users SET password=? WHERE email=?`, [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'`,
//       [email],
//     );

//     console.log("[RESET-PASSWORD] Committing...");
//     await connection.commit();
//     res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });
//   } catch (err) {
//     console.log("[RESET-PASSWORD] Catch block triggered.");
//     await connection.rollback();
//     logError("ResetPassword", err);
//     res
//       .status(500)
//       .json({
//         success: false,
//         message: `Reset failed: ${err instanceof Error ? err.message : String(err)}`,
//       });
//   } finally {
//     connection.release();
//     console.log("[RESET-PASSWORD] Connection released.");
//   }
// };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import crypto from "crypto"; // Added for secure random generation
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// /*
// INTERFACES
// */
// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// interface OTPRow extends RowDataPacket {
//   otp_hash: string;
//   expires_at: Date;
// }

// /*
// REGEX & UTILS
// */
// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
// const mobileRegex = /^[0-9]{10}$/;

// const normalizeEmail = (email: string) => email.trim().toLowerCase();

// // Error Logger Utility
// const logError = (context: string, err: any) => {
//   console.error(
//     `[ERROR][${new Date().toISOString()}] ${context}:`,
//     err.message || err,
//   );
// };

// /*
// REGISTER
// */
// export const register = async (req: Request, res: Response) => {
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!name || !email || !password || !mobile_no) {
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   if (!emailRegex.test(email))
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid email format" });
//   if (!passwordRegex.test(password))
//     return res.status(400).json({ success: false, message: "Weak password" });
//   if (!mobileRegex.test(mobile_no))
//     return res.status(400).json({ success: false, message: "Invalid mobile" });

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (exist.length > 0) {
//       await connection.rollback();
//       return res
//         .status(409)
//         .json({ success: false, message: "Email already registered" });
//     }

//     const hashed = await bcrypt.hash(password, 10);
//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     // Secure OTP Generation
//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'register', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res
//       .status(201)
//       .json({ success: true, message: "Registration successful. OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     logError("Register", err);
//     res
//       .status(500)
//       .json({
//         success: false,
//         message: "Internal server error during registration",

//       });
//   } finally {
//     connection.release();
//   }
// };

// /*
// VERIFY OTP
// */
// export const verifyOTP = async (req: Request, res: Response) => {
//   const email = normalizeEmail(req.body.email || "");
//   const { otp } = req.body;

//   // OTP Length Validation
//   if (!otp || String(otp).length !== 6) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid OTP length" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='register' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       await connection.rollback();
//       return res
//         .status(410)
//         .json({ success: false, message: "OTP expired or not found" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Incorrect OTP" });
//     }

//     await connection.query(`UPDATE users SET is_verified=1 WHERE email=?`, [
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='register'`,
//       [email],
//     );

//     const [userRows] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );
//     await connection.commit();

//     const token = generateToken(userRows[0].id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     res
//       .status(200)
//       .json({ success: true, message: "Account verified successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("VerifyOTP", err);
//     res.status(500).json({ success: false, message: "Verification failed" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGIN
// */
// export const login = async (req: Request, res: Response) => {
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const { password } = req.body;

//     if (!email || !password)
//       return res
//         .status(400)
//         .json({ success: false, message: "Credentials required" });

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );
//     if (rows.length === 0)
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid credentials" });

//     const user = rows[0];
//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid)
//       return res
//         .status(401)
//         .json({ success: false, message: "Invalid credentials" });

//     if (user.is_verified === 0)
//       return res
//         .status(403)
//         .json({ success: false, message: "Please verify your account first" });

//     const token = generateToken(user.id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     res.status(200).json({ success: true, message: "Login successful" });
//   } catch (err) {
//     logError("Login", err);
//     res
//       .status(500)
//       .json({ success: false, message: "Server error during login" });
//   }
// };

// /*
// FORGOT PASSWORD
// */
// export const forgotPassword = async (req: Request, res: Response) => {
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     if (!emailRegex.test(email))
//       return res
//         .status(400)
//         .json({ success: false, message: "Valid email required" });

//     const [users] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     // Anti-enumeration: 200 OK even if email doesn't exist
//     if (users.length === 0) {
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, OTP sent" });
//     }

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await pool.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'`,
//       [email],
//     );
//     await pool.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', 'reset_password', ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     res
//       .status(200)
//       .json({ success: true, message: "If account exists, OTP sent" });
//   } catch (err) {
//     logError("ForgotPassword", err);
//     res
//       .status(500)
//       .json({ success: false, message: "Error processing request" });
//   }
// };

// /*
// RESET PASSWORD
// */
// export const resetPassword = async (req: Request, res: Response) => {
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   if (String(otp).length !== 6)
//     return res
//       .status(400)
//       .json({ success: false, message: "Invalid OTP format" });
//   if (!passwordRegex.test(newPassword))
//     return res
//       .status(400)
//       .json({ success: false, message: "Weak new password" });

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       await connection.rollback();
//       return res.status(410).json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       await connection.rollback();
//       return res.status(401).json({ success: false, message: "Invalid OTP" });
//     }

//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query(`UPDATE users SET password=? WHERE email=?`, [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND purpose='reset_password'`,
//       [email],
//     );

//     await connection.commit();
//     res
//       .status(200)
//       .json({ success: true, message: "Password updated successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("ResetPassword", err);
//     res
//       .status(500)
//       .json({ success: false, message: "Failed to reset password" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGOUT
// */
// export const logout = (req: Request, res: Response) => {
//   res.clearCookie("token", {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "strict",
//   });
//   res.status(200).json({ success: true, message: "Logged out" });
// };

// /*
// RESEND OTP
// */
// export const resendOTP = async (req: Request, res: Response) => {
//   const { purpose } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!email || !["register", "reset_password"].includes(purpose)) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Email and valid purpose required" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [user] = await connection.query<UserRow[]>(
//       "SELECT is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (user.length === 0) {
//       await connection.rollback();
//       return res
//         .status(200)
//         .json({ success: true, message: "If account exists, new OTP sent" });
//     }

//     if (purpose === "register" && user[0].is_verified === 1) {
//       await connection.rollback();
//       return res
//         .status(400)
//         .json({ success: false, message: "Account already verified" });
//     }

//     // Rate Limiting Check (1 Minute)
//     const [existingOTP] = await connection.query<RowDataPacket[]>(
//       "SELECT created_at FROM otp_codes WHERE email=? AND purpose=? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
//       [email, purpose],
//     );

//     if (existingOTP.length > 0) {
//       await connection.rollback();
//       return res
//         .status(429)
//         .json({ success: false, message: "Wait 1 minute before resending" });
//     }

//     const otp = crypto.randomInt(100000, 999999);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose=?",
//       [email, purpose],
//     );
//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, purpose, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res.status(200).json({ success: true, message: "OTP resent successfully" });
//   } catch (err) {
//     await connection.rollback();
//     logError("ResendOTP", err);
//     res.status(500).json({ success: false, message: "Resend failed" });
//   } finally {
//     connection.release();
//   }
// };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// /*
// INTERFACES
// */
// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// interface OTPRow extends RowDataPacket {
//   otp_hash: string;
//   expires_at: Date;
// }

// /*
// REGEX & UTILS
// */
// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
// const mobileRegex = /^[0-9]{10}$/;

// const normalizeEmail = (email: string) => email.trim().toLowerCase();

// /*
// REGISTER
// */
// export const register = async (req: Request, res: Response) => {
//   const { name, password, mobile_no } = req.body;
//   const email = normalizeEmail(req.body.email || "");

//   if (!name || !email || !password || !mobile_no) {
//     return res
//       .status(400)
//       .json({ success: false, message: "All fields required" });
//   }

//   if (!emailRegex.test(email))
//     return res.status(400).json({ success: false, message: "Invalid email" });
//   if (!passwordRegex.test(password))
//     return res.status(400).json({ success: false, message: "Weak password" });
//   if (!mobileRegex.test(mobile_no))
//     return res.status(400).json({ success: false, message: "Invalid mobile" });

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [exist] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );
//     if (exist.length > 0) {
//       await connection.rollback();
//       return res.json({ success: false, message: "Email exists" });
//     }

//     const hashed = await bcrypt.hash(password, 10);
//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified) VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     const otp = Math.floor(100000 + Math.random() * 900000);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND role='user' AND purpose='register'`,
//       [email],
//     );

//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, "user", "register", otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res.json({ success: true, message: "OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     res.status(500).json({ success: false, message: "Register error" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// VERIFY OTP (Transaction Added)
// */
// export const verifyOTP = async (req: Request, res: Response) => {
//   const email = normalizeEmail(req.body.email || "");
//   const otp = req.body.otp;

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND role='user' AND purpose='register' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       await connection.rollback();
//       return res.json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       await connection.rollback();
//       return res.json({ success: false, message: "Invalid OTP" });
//     }

//     await connection.query(`UPDATE users SET is_verified=1 WHERE email=?`, [
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND role='user' AND purpose='register'`,
//       [email],
//     );

//     const [userRows] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     await connection.commit();

//     const token = generateToken(userRows[0].id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     res.json({ success: true, message: "Verified" });
//   } catch (err) {
//     await connection.rollback();
//     res.status(500).json({ success: false, message: "Verification error" });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGIN
// */
// export const login = async (req: Request, res: Response) => {
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const password = req.body.password;

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );
//     if (rows.length === 0)
//       return res.json({ success: false, message: "Invalid login" });

//     const user = rows[0];
//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid) return res.json({ success: false, message: "Invalid login" });

//     if (user.is_verified === 0)
//       return res.json({ success: false, message: "Verify account" });

//     const token = generateToken(user.id);
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     res.json({ success: true, message: "Login success" });
//   } catch (err) {
//     res.status(500).json({ success: false, message: "Server error" });
//   }
// };

// /*
// FORGOT PASSWORD
// */
// export const forgotPassword = async (req: Request, res: Response) => {
//   try {
//     const email = normalizeEmail(req.body.email || "");
//     const [users] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     // Anti-enumeration: return success even if user doesn't exist
//     if (users.length === 0) {
//       return res.json({ success: true, message: "If account exists OTP sent" });
//     }

//     const otp = Math.floor(100000 + Math.random() * 900000);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     await pool.query(
//       `DELETE FROM otp_codes WHERE email=? AND role='user' AND purpose='reset_password'`,
//       [email],
//     );

//     await pool.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, "user", "reset_password", otpHash],
//     );

//     await sendOTPEmail(email, otp);
//     res.json({ success: true, message: "If account exists OTP sent" });
//   } catch (err) {
//     res.status(500).json({ success: false });
//   }
// };

// /*
// RESET PASSWORD (Transaction Added)
// */
// export const resetPassword = async (req: Request, res: Response) => {
//   const email = normalizeEmail(req.body.email || "");
//   const { otp, password: newPassword } = req.body;

//   if (!passwordRegex.test(newPassword)) {
//     return res.status(400).json({ success: false, message: "Weak password" });
//   }

//   const connection = await pool.getConnection();
//   try {
//     await connection.beginTransaction();

//     const [rows] = await connection.query<OTPRow[]>(
//       `SELECT otp_hash FROM otp_codes WHERE email=? AND role='user' AND purpose='reset_password' AND expires_at > NOW() FOR UPDATE`,
//       [email],
//     );

//     if (rows.length === 0) {
//       await connection.rollback();
//       return res.json({ success: false, message: "OTP expired" });
//     }

//     const valid = await bcrypt.compare(String(otp), rows[0].otp_hash);
//     if (!valid) {
//       await connection.rollback();
//       return res.json({ success: false, message: "Invalid OTP" });
//     }

//     const hashed = await bcrypt.hash(newPassword, 10);
//     await connection.query(`UPDATE users SET password=? WHERE email=?`, [
//       hashed,
//       email,
//     ]);
//     await connection.query(
//       `DELETE FROM otp_codes WHERE email=? AND role='user' AND purpose='reset_password'`,
//       [email],
//     );

//     await connection.commit();
//     res.json({ success: true, message: "Password updated" });
//   } catch (err) {
//     await connection.rollback();
//     res.status(500).json({ success: false });
//   } finally {
//     connection.release();
//   }
// };

// /*
// LOGOUT
// */
// export const logout = (req: Request, res: Response) => {
//   try {
//     res.clearCookie("token", {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "strict",
//     });
//     res.json({ success: true });
//   } catch {
//     res.status(500).json({ success: false });
//   }
// };

// /*
// resend OTP
// */

// export const resendOTP = async (req: Request, res: Response) => {
//   const { purpose } = req.body; // 'register' or 'reset_password'
//   const email = normalizeEmail(req.body.email || "");

//   if (!email || !purpose) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Email and purpose required" });
//   }

//   const connection = await pool.getConnection();

//   try {
//     await connection.beginTransaction();

//     // 1. Verify purpose and user status
//     const [user] = await connection.query<UserRow[]>(
//       "SELECT is_verified FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (user.length === 0) {
//       await connection.rollback();
//       // Anti-enumeration: Don't reveal if user exists
//       return res.json({
//         success: true,
//         message: "If account exists, new OTP sent",
//       });
//     }

//     // 2. Prevent resending if already verified (for registration)
//     if (purpose === "register" && user[0].is_verified === 1) {
//       await connection.rollback();
//       return res
//         .status(400)
//         .json({ success: false, message: "Account already verified" });
//     }

//     // 3. Optional: Rate limiting check (e.g., don't send if last OTP was created < 1 minute ago)
//     const [existingOTP] = await connection.query<RowDataPacket[]>(
//       "SELECT created_at FROM otp_codes WHERE email=? AND purpose=? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
//       [email, purpose],
//     );

//     if (existingOTP.length > 0) {
//       await connection.rollback();
//       return res
//         .status(429)
//         .json({
//           success: false,
//           message: "Please wait 1 minute before resending",
//         });
//     }

//     // 4. Generate new OTP
//     const otp = Math.floor(100000 + Math.random() * 900000);
//     const otpHash = await bcrypt.hash(String(otp), 10);

//     // 5. Update the database
//     await connection.query(
//       "DELETE FROM otp_codes WHERE email=? AND purpose=?",
//       [email, purpose],
//     );

//     await connection.query(
//       `INSERT INTO otp_codes (email, role, purpose, otp_hash, expires_at)
//        VALUES (?, 'user', ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
//       [email, purpose, otpHash],
//     );

//     await connection.commit();
//     await sendOTPEmail(email, otp);

//     res.json({ success: true, message: "New OTP sent" });
//   } catch (err) {
//     await connection.rollback();
//     res.status(500).json({ success: false, message: "Resend error" });
//   } finally {
//     connection.release();
//   }
// };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// // Interfaces

// interface OTPRecord {
//   otp: number;
//   expiresAt: number;
//   lastSent: number;
// }

// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// // Memory Stores

// const otpStore = new Map<string, OTPRecord>();
// const loginAttempts = new Map<string, number>();

// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
// const mobileRegex = /^[0-9]{10}$/;

// /**
//  * REGISTER
//  */
// export const register = async (req: Request, res: Response) => {
//   const { name, email, password, mobile_no } = req.body;

//   if (!name || !email || !password || !mobile_no) {
//     return res.status(400).json({
//       success: false,
//       message: "All fields required",
//     });
//   }

//   if (!emailRegex.test(email)) {
//     return res.status(400).json({
//       success: false,
//       message: "Invalid Email",
//     });
//   }

//   if (!passwordRegex.test(password)) {
//     return res.status(400).json({
//       success: false,
//       message: "Weak Password",
//     });
//   }

//   if (!mobileRegex.test(mobile_no)) {
//     return res.status(400).json({
//       success: false,
//       message: "Invalid Mobile",
//     });
//   }

//   const connection = await pool.getConnection();

//   try {
//     await connection.beginTransaction();

//     const [existing] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (existing.length > 0) {
//       await connection.rollback();

//       return res.status(400).json({
//         success: false,
//         message: "Email Exists",
//       });
//     }

//     const hashed = await bcrypt.hash(password, 10);

//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users
//        (name,email,password,mobile_no,is_verified)
//        VALUES (?,?,?,?,0)`,

//       [name, email, hashed, mobile_no],
//     );

//     await connection.commit();

//     const otp = Math.floor(100000 + Math.random() * 900000);

//     const expiresAt = Date.now() + 60000;

//     const lastSent = Date.now();

//     otpStore.set(email, {
//       otp,
//       expiresAt,
//       lastSent,
//     });

//     setTimeout(() => {
//       otpStore.delete(email);
//     }, 60000);

//     await sendOTPEmail(email, otp);

//     res.status(201).json({
//       success: true,
//       message: "OTP Sent",
//     });
//   } catch (error) {
//     console.error("Register Error:", error);

//     await connection.rollback();

//     res.status(500).json({
//       success: false,
//       message: "Register Error",
//     });
//   } finally {
//     connection.release();
//   }
// };

// /**
//  * VERIFY OTP
//  */

// export const verifyOTP = async (req: Request, res: Response) => {
//   const { email, otp } = req.body;

//   const record = otpStore.get(email);

//   if (!record) {
//     return res.status(400).json({
//       success: false,
//       message: "OTP Missing",
//     });
//   }

//   if (Date.now() > record.expiresAt) {
//     otpStore.delete(email);

//     return res.status(400).json({
//       success: false,
//       message: "Expired",
//     });
//   }

//   if (record.otp !== Number(otp)) {
//     return res.status(400).json({
//       success: false,
//       message: "Invalid OTP",
//     });
//   }

//   try {
//     await pool.query("UPDATE users SET is_verified=1 WHERE email=?", [email]);

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     const user = rows[0];

//     const token = generateToken(user.id);

//     res.cookie("token", token, {
//       httpOnly: true,

//       secure: process.env.NODE_ENV === "production",

//       sameSite: "strict",

//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     otpStore.delete(email);

//     res.json({
//       success: true,

//       message: "Verified",
//     });
//   } catch (error) {
//     console.error("Verification Error:", error);

//     res.status(500).json({
//       success: false,

//       message: "Verification Error",
//     });
//   }
// };

// /**
//  * RESEND OTP
//  */
// export const resendOTP = async (req: Request, res: Response) => {
//   try {
//     const { email } = req.body;

//     const existing = otpStore.get(email);

//     if (existing) {
//       const diff = Date.now() - existing.lastSent;

//       if (diff < 30000) {
//         return res.status(429).json({
//           success: false,
//           message: "Wait 30 sec",
//         });
//       }
//     }

//     const otp = Math.floor(100000 + Math.random() * 900000);

//     const expiresAt = Date.now() + 60000;

//     const lastSent = Date.now();

//     otpStore.set(email, {
//       otp,
//       expiresAt,
//       lastSent,
//     });

//     setTimeout(() => {
//       otpStore.delete(email);
//     }, 60000);

//     await sendOTPEmail(email, otp);

//     res.json({
//       success: true,
//       message: "OTP Sent",
//     });
//   } catch (error) {
//     console.error("Resend OTP Error:", error);

//     res.status(500).json({
//       success: false,
//       message: "Server Error",
//     });
//   }
// };

// /**
//  * LOGIN
//  */
// export const login = async (req: Request, res: Response) => {
//   try {
//     const { email, password } = req.body;

//     const attempts = loginAttempts.get(email) || 0;

//     if (attempts >= 5) {
//       return res.status(429).json({
//         success: false,
//         message: "Too Many Attempts",
//       });
//     }

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT * FROM users WHERE email=?",
//       [email],
//     );

//     const user = rows[0];

//     if (!user || !(await bcrypt.compare(password, user.password))) {
//       loginAttempts.set(email, attempts + 1);

//       setTimeout(() => {
//         loginAttempts.delete(email);
//       }, 600000);

//       return res.status(401).json({
//         success: false,
//         message: "Invalid Login",
//       });
//     }

//     if (user.is_verified === 0) {
//       return res.status(403).json({
//         success: false,
//         message: "Verify Account",
//       });
//     }

//     const token = generateToken(user.id);

//     res.cookie("token", token, {
//       httpOnly: true,

//       secure: process.env.NODE_ENV === "production",

//       sameSite: "strict",

//       maxAge: 7 * 24 * 60 * 60 * 1000,
//     });

//     loginAttempts.delete(email);

//     res.json({
//       success: true,

//       message: "Login Success",

//       user: {
//         id: user.id,
//         name: user.name,
//         email: user.email,
//       },
//     });
//   } catch (error) {
//     console.error("Login Error:", error);

//     res.status(500).json({
//       success: false,

//       message: "Server Error",
//     });
//   }
// };

// /**
//  * LOGOUT
//  */
// export const logout = (req: Request, res: Response) => {
//   try {
//     res.clearCookie("token", {
//       httpOnly: true,

//       secure: process.env.NODE_ENV === "production",

//       sameSite: "strict",
//     });

//     res.json({
//       success: true,

//       message: "Logged out successfully",
//     });
//   } catch (error) {
//     console.error("Logout Error:", error);

//     res.status(500).json({
//       success: false,

//       message: "Logout Failed",
//     });
//   }
// };

// import { Request, Response } from "express";
// import bcrypt from "bcrypt";
// import { RowDataPacket, ResultSetHeader } from "mysql2";

// import { pool } from "../config/db.js";
// import { sendOTPEmail } from "../config/mailer.js";
// import { generateToken } from "../utils/jwt.js";

// // --- Interfaces ---

// interface OTPRecord {
//   otp: number;
//   expiresAt: number;
//   lastSent: number;
// }

// interface UserRow extends RowDataPacket {
//   id: number;
//   name: string;
//   email: string;
//   password: string;
//   mobile_no: string;
//   is_verified: number;
// }

// // --- Memory Stores & Helpers ---

// const otpStore = new Map<string, OTPRecord>();
// const loginAttempts = new Map<string, number>();

// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
// const mobileRegex = /^[0-9]{10}$/;

// // --- Controller Functions ---

// /**
//  * REGISTER
//  */
// export const register = async (req: Request, res: Response) => {
//   const { name, email, password, mobile_no } = req.body;

//   // Validation
//   if (!name || !email || !password || !mobile_no) {
//     return res.status(400).json({
//       success: false,
//       message: "All fields required",
//     });
//   }

//   if (!emailRegex.test(email)) {
//     return res.status(400).json({ success: false, message: "Invalid Email" });
//   }

//   if (!passwordRegex.test(password)) {
//     return res.status(400).json({ success: false, message: "Weak Password" });
//   }

//   if (!mobileRegex.test(mobile_no)) {
//     return res.status(400).json({ success: false, message: "Invalid Mobile" });
//   }

//   const connection = await pool.getConnection();

//   try {
//     await connection.beginTransaction();

//     // Check for existing user
//     const [existing] = await connection.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=? FOR UPDATE",
//       [email],
//     );

//     if (existing.length > 0) {
//       await connection.rollback();
//       return res.status(400).json({
//         success: false,
//         message: "Email Exists",
//       });
//     }

//     const hashed = await bcrypt.hash(password, 10);

//     await connection.query<ResultSetHeader>(
//       `INSERT INTO users (name, email, password, mobile_no, is_verified)
//              VALUES (?, ?, ?, ?, 0)`,
//       [name, email, hashed, mobile_no],
//     );

//     await connection.commit();

//     // OTP Generation
//     const otp = Math.floor(100000 + Math.random() * 900000);
//     const expiresAt = Date.now() + 60000; // 1 minute
//     const lastSent = Date.now();

//     otpStore.set(email, { otp, expiresAt, lastSent });

//     // Auto-delete OTP after 1 minute
//     setTimeout(() => {
//       otpStore.delete(email);
//     }, 60000);

//     await sendOTPEmail(email, otp);

//     res.status(201).json({
//       success: true,
//       message: "OTP Sent",
//     });
//   } catch (error) {
//     await connection.rollback();
//     res.status(500).json({
//       success: false,
//       message: "Register Error",
//     });
//   } finally {
//     connection.release();
//   }
// };

// /**
//  * VERIFY OTP
//  */
// export const verifyOTP = async (req: Request, res: Response) => {
//   const { email, otp } = req.body;
//   const record = otpStore.get(email);

//   if (!record) {
//     return res.status(400).json({
//       success: false,
//       message: "OTP Missing",
//     });
//   }

//   if (Date.now() > record.expiresAt) {
//     otpStore.delete(email);
//     return res.status(400).json({
//       success: false,
//       message: "Expired",
//     });
//   }

//   if (record.otp !== Number(otp)) {
//     return res.status(400).json({
//       success: false,
//       message: "Invalid OTP",
//     });
//   }

//   try {
//     await pool.query("UPDATE users SET is_verified=1 WHERE email=?", [email]);

//     const [rows] = await pool.query<UserRow[]>(
//       "SELECT id FROM users WHERE email=?",
//       [email],
//     );

//     const user = rows[0];
//     const token = generateToken(user.id);

//     res.cookie("token", token, {
//       httpOnly: true,
//       maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//     });

//     otpStore.delete(email);

//     res.json({
//       success: true,
//       message: "Verified",
//     });
//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: "Verification Error",
//     });
//   }
// };

// /**
//  * RESEND OTP
//  */
// export const resendOTP = async (req: Request, res: Response) => {
//   const { email } = req.body;
//   const existing = otpStore.get(email);

//   if (existing) {
//     const diff = Date.now() - existing.lastSent;
//     if (diff < 30000) {
//       return res.status(429).json({
//         success: false,
//         message: "Wait 30 sec",
//       });
//     }
//   }

//   const otp = Math.floor(100000 + Math.random() * 900000);
//   const expiresAt = Date.now() + 60000;
//   const lastSent = Date.now();

//   otpStore.set(email, { otp, expiresAt, lastSent });

//   setTimeout(() => {
//     otpStore.delete(email);
//   }, 60000);

//   await sendOTPEmail(email, otp);

//   res.json({
//     success: true,
//     message: "OTP Sent",
//   });
// };

// /**
//  * LOGIN
//  */
// export const login = async (req: Request, res: Response) => {
//   const { email, password } = req.body;
//   const attempts = loginAttempts.get(email) || 0;

//   if (attempts >= 5) {
//     return res.status(429).json({
//       success: false,
//       message: "Too Many Attempts",
//     });
//   }

//   const [rows] = await pool.query<UserRow[]>(
//     "SELECT * FROM users WHERE email=?",
//     [email],
//   );

//   const user = rows[0];

//   if (!user || !(await bcrypt.compare(password, user.password))) {
//     loginAttempts.set(email, attempts + 1);

//     setTimeout(() => {
//       loginAttempts.delete(email);
//     }, 600000); // 10 minutes lock

//     return res.status(401).json({
//       success: false,
//       message: "Invalid Login",
//     });
//   }

//   if (user.is_verified === 0) {
//     return res.status(403).json({
//       success: false,
//       message: "Verify Account",
//     });
//   }

//   const token = generateToken(user.id);

//   res.cookie("token", token, {
//     httpOnly: true,
//     maxAge: 7 * 24 * 60 * 60 * 1000,
//   });

//   loginAttempts.delete(email);

//   res.json({
//     success: true,
//     message: "Login Success",
//     user: {
//       id: user.id,
//       name: user.name,
//       email: user.email,
//     },
//   });
// };
