import jwt from "jsonwebtoken";

// Validate JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("❌ JWT_SECRET is missing in .env file");
}

/**
 * Generate JWT Token
 */
export const generateToken = (id: number): string => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: "7d",
  });
};
