import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { RowDataPacket, ResultSetHeader } from "mysql2";

import { pool } from "../config/db.js";
import { sendOTPEmail } from "../config/mailer.js";
import { generateToken } from "../utils/jwt.js";

// Interfaces

interface OTPRecord {
  otp: number;
  expiresAt: number;
  lastSent: number;
}

interface UserRow extends RowDataPacket {
  id: number;
  name: string;
  email: string;
  password: string;
  mobile_no: string;
  is_verified: number;
}

// Memory Stores

const otpStore = new Map<string, OTPRecord>();
const loginAttempts = new Map<string, number>();

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
const mobileRegex = /^[0-9]{10}$/;

/**
 * REGISTER
 */
export const register = async (req: Request, res: Response) => {
  const { name, email, password, mobile_no } = req.body;

  if (!name || !email || !password || !mobile_no) {
    return res.status(400).json({
      success: false,
      message: "All fields required",
    });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      message: "Invalid Email",
    });
  }

  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      success: false,
      message: "Weak Password",
    });
  }

  if (!mobileRegex.test(mobile_no)) {
    return res.status(400).json({
      success: false,
      message: "Invalid Mobile",
    });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [existing] = await connection.query<UserRow[]>(
      "SELECT id FROM users WHERE email=? FOR UPDATE",
      [email],
    );

    if (existing.length > 0) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message: "Email Exists",
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    await connection.query<ResultSetHeader>(
      `INSERT INTO users 
       (name,email,password,mobile_no,is_verified)
       VALUES (?,?,?,?,0)`,

      [name, email, hashed, mobile_no],
    );

    await connection.commit();

    const otp = Math.floor(100000 + Math.random() * 900000);

    const expiresAt = Date.now() + 60000;

    const lastSent = Date.now();

    otpStore.set(email, {
      otp,
      expiresAt,
      lastSent,
    });

    setTimeout(() => {
      otpStore.delete(email);
    }, 60000);

    await sendOTPEmail(email, otp);

    res.status(201).json({
      success: true,
      message: "OTP Sent",
    });
  } catch (error) {
    console.error("Register Error:", error);

    await connection.rollback();

    res.status(500).json({
      success: false,
      message: "Register Error",
    });
  } finally {
    connection.release();
  }
};

/**
 * VERIFY OTP
 */

export const verifyOTP = async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  const record = otpStore.get(email);

  if (!record) {
    return res.status(400).json({
      success: false,
      message: "OTP Missing",
    });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);

    return res.status(400).json({
      success: false,
      message: "Expired",
    });
  }

  if (record.otp !== Number(otp)) {
    return res.status(400).json({
      success: false,
      message: "Invalid OTP",
    });
  }

  try {
    await pool.query("UPDATE users SET is_verified=1 WHERE email=?", [email]);

    const [rows] = await pool.query<UserRow[]>(
      "SELECT id FROM users WHERE email=?",
      [email],
    );

    const user = rows[0];

    const token = generateToken(user.id);

    res.cookie("token", token, {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    otpStore.delete(email);

    res.json({
      success: true,

      message: "Verified",
    });
  } catch (error) {
    console.error("Verification Error:", error);

    res.status(500).json({
      success: false,

      message: "Verification Error",
    });
  }
};

/**
 * RESEND OTP
 */
export const resendOTP = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    const existing = otpStore.get(email);

    if (existing) {
      const diff = Date.now() - existing.lastSent;

      if (diff < 30000) {
        return res.status(429).json({
          success: false,
          message: "Wait 30 sec",
        });
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    const expiresAt = Date.now() + 60000;

    const lastSent = Date.now();

    otpStore.set(email, {
      otp,
      expiresAt,
      lastSent,
    });

    setTimeout(() => {
      otpStore.delete(email);
    }, 60000);

    await sendOTPEmail(email, otp);

    res.json({
      success: true,
      message: "OTP Sent",
    });
  } catch (error) {
    console.error("Resend OTP Error:", error);

    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

/**
 * LOGIN
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const attempts = loginAttempts.get(email) || 0;

    if (attempts >= 5) {
      return res.status(429).json({
        success: false,
        message: "Too Many Attempts",
      });
    }

    const [rows] = await pool.query<UserRow[]>(
      "SELECT * FROM users WHERE email=?",
      [email],
    );

    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      loginAttempts.set(email, attempts + 1);

      setTimeout(() => {
        loginAttempts.delete(email);
      }, 600000);

      return res.status(401).json({
        success: false,
        message: "Invalid Login",
      });
    }

    if (user.is_verified === 0) {
      return res.status(403).json({
        success: false,
        message: "Verify Account",
      });
    }

    const token = generateToken(user.id);

    res.cookie("token", token, {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    loginAttempts.delete(email);

    res.json({
      success: true,

      message: "Login Success",

      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);

    res.status(500).json({
      success: false,

      message: "Server Error",
    });
  }
};

/**
 * LOGOUT
 */
export const logout = (req: Request, res: Response) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: "strict",
    });

    res.json({
      success: true,

      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout Error:", error);

    res.status(500).json({
      success: false,

      message: "Logout Failed",
    });
  }
};








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
