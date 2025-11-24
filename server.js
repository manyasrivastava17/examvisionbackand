// ==========================
//  FULL BACKEND (SINGLE FILE)
//  ExamVision Backend
// ==========================

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();

// ========== ENV CONFIG ==========
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

const UPLOAD_DIR = "./uploads";
const ID_DIR = "./uploads/id-cards";
const FRAME_DIR = "./uploads/frames";

// ========== CREATE DIRECTORIES ==========
[UPLOAD_DIR, ID_DIR, FRAME_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ========== MIDDLEWARE ==========
app.use(helmet());
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(mongoSanitize());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ========== MONGOOSE MODELS ==========
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  idCard: { filename: String, path: String, uploadedAt: Date },
});

UserSchema.methods.comparePassword = function (pw) {
  return bcrypt.compare(pw, this.password);
};

const User = mongoose.model("User", UserSchema);

const SessionSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  sessionId: String,
  startedAt: Date,
  completedAt: Date,
  totalAlerts: Number,
  frames: [{ path: String, timestamp: Date }],
  suspicious: [
    { type: String, message: String, timestamp: Date, framePath: String },
  ],
  status: String,
});

const Session = mongoose.model("Session", SessionSchema);

// ========== AUTH MIDDLEWARE ==========
function auth(req, res, next) {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token)
      return res.status(401).json({ success: false, message: "No token." });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired token." });
  }
}

// ========== GENERATE JWT ==========
function generateToken(id) {
  return jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: "2h" });
}

// ========== MULTER FOR ID UPLOAD ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, ID_DIR);
  },
  filename: (req, file, cb) => {
    cb(
      null,
      `id-${req.user.userId}-${Date.now()}${path.extname(file.originalname)}`
    );
  },
});

const upload = multer({ storage });

// ========== AI MOCK ANALYZER ==========
function analyzeFrame() {
  const cases = [
    { alert: false, type: "normal", message: "Everything OK" },
    { alert: true, type: "no_face", message: "No face detected" },
    { alert: true, type: "multiple_faces", message: "Multiple faces detected" },
    { alert: true, type: "looking_away", message: "Looking away" },
    { alert: true, type: "movement", message: "Suspicious movement" },
  ];
  return cases[Math.floor(Math.random() * cases.length)];
}

// =============================
//         AUTH ROUTES
// =============================

// SIGNUP
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.json({ success: false, message: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ success: false, message: "Email exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash });

    const token = generateToken(user._id);

    res.json({ success: true, token, user });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false, message: "Invalid credentials" });

  const match = await user.comparePassword(password);
  if (!match) return res.json({ success: false, message: "Invalid credentials" });

  const token = generateToken(user._id);
  res.json({ success: true, token, user });
});

// =============================
//       UPLOAD ID CARD
// =============================
app.post("/api/upload/id-card", auth, upload.single("idCard"), async (req, res) => {
  const user = await User.findById(req.user.userId);
  user.idCard = {
    filename: req.file.filename,
    path: `/uploads/id-cards/${req.file.filename}`,
    uploadedAt: new Date(),
  };
  await user.save();
  res.json({ success: true, file: user.idCard });
});

// =============================
//         EXAM ROUTES
// =============================

// Start exam
app.post("/api/exam/start", auth, async (req, res) => {
  const sessionId = `sess-${Date.now()}`;
  await Session.create({
    userId: req.user.userId,
    sessionId,
    startedAt: new Date(),
    status: "active",
    totalAlerts: 0,
  });
  res.json({ success: true, sessionId });
});

// Frame limiter (1/sec)
const limiter = rateLimit({
  windowMs: 1000,
  max: 1,
});

// Send frame
app.post("/api/exam/frame", auth, limiter, async (req, res) => {
  const { sessionId, frame } = req.body;

  const session = await Session.findOne({ sessionId });
  if (!session) return res.json({ success: false, message: "No session" });

  const base64 = frame.replace(/^data:image\/\w+;base64,/, "");
  const buffer = Buffer.from(base64, "base64");
  const filename = `frame-${Date.now()}.jpg`;
  fs.writeFileSync(`${FRAME_DIR}/${filename}`, buffer);

  const ai = analyzeFrame();

  session.frames.push({ path: `/uploads/frames/${filename}`, timestamp: new Date() });

  if (ai.alert) {
    session.suspicious.push({
      type: ai.type,
      message: ai.message,
      timestamp: new Date(),
      framePath: `/uploads/frames/${filename}`,
    });
    session.totalAlerts += 1;
  }

  await session.save();

  res.json({ success: true, ai });
});

// Submit exam
app.post("/api/exam/submit", auth, async (req, res) => {
  const { sessionId } = req.body;
  const session = await Session.findOne({ sessionId });
  session.completedAt = new Date();
  session.status = "completed";
  await session.save();
  res.json({ success: true, session });
});

// =============================
//         ADMIN ROUTES
// =============================
app.get("/api/admin/sessions", auth, async (req, res) => {
  const sessions = await Session.find().populate("userId");
  res.json({ success: true, sessions });
});

// =============================
//          HEALTH CHECK
// =============================
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Backend Running" });
});

// =============================
//       START SERVER
// =============================
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected");
    app.listen(PORT, () => console.log(`SERVER RUNNING ON PORT ${PORT}`));
  })
  .catch((err) => console.error(err));