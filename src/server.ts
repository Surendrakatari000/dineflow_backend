import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser"; // Added
import { connectDB } from "./config/db.js";
import userRoutes from "./routes/userAuthRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL, // Recommended: specify your frontend URL
    credentials: true, // Required for cookies to work with CORS
  }),
);
app.use(express.json());
app.use(cookieParser()); // Added: Essential for res.cookie/res.clearCookie

// Initialize Database
connectDB();

app.use("/user/auth/", userRoutes);

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
