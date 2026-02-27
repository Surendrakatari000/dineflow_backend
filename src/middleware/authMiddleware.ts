import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  let token;

  // 1. Get token from cookies
  token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Not authorized, please login" });
  }

  try {
    // 2. Verify token
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET as string);

    // 3. Attach user info to the request (ID and Role)
    // We cast it to any so we can add properties to the req object
    (req as any).user = {
      id: decoded.id,
    };

    next();
  } catch (error) {
    res.status(401).json({ message: "Token is not valid" });
  }
};
