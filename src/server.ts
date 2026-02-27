import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import { connectDB } from "./config/db.js";
import userRoutes from "./routes/userAuthRoutes.js";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// 1. Middleware Configuration
app.use(
  cors({
    // Ensure CLIENT_URL in your .env is http://localhost:5173 (no trailing slash)
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true, // Required for cookies/sessions to work across origins
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// 2. Body Parsing Middleware (Must be before routes)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 3. Initialize Database
connectDB();

// 4. API Routes
app.use("/user/auth", userRoutes);

// Root Route for testing
app.get("/", (req, res) => {
  res.send("🚀 API is running...");
});

// 5. Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(
    `👉 Accepting requests from: ${process.env.CLIENT_URL || "http://localhost:5173"}`,
  );
});

// import express from "express";
// import cors from "cors";
// import dotenv from "dotenv";
// import cookieParser from "cookie-parser"; // Added
// import { connectDB } from "./config/db.js";
// import userRoutes from "./routes/userAuthRoutes.js";

// dotenv.config();

// const app = express();
// const PORT = process.env.PORT || 5000;

// // Middleware
// app.use(
//   cors({
//     origin: process.env.CLIENT_URL, // Recommended: specify your frontend URL
//     credentials: true, // Required for cookies to work with CORS
//   }),
// );
// app.use(express.json());
// app.use(cookieParser()); // Added: Essential for res.cookie/res.clearCookie

// // Initialize Database
// connectDB();

// app.use("/user/auth/", userRoutes);

// app.listen(PORT, () => {
//   console.log(`🚀 Server running on http://localhost:${PORT}`);
// });
