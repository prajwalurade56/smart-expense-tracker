
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

if (!process.env.DB_PASSWORD || !process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set DB_PASSWORD and a SESSION_SECRET of at least 32 characters in .env");
}

const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "expense_tracker"
};

const pool = mysql.createPool({
  ...dbConfig,
  waitForConnections: true,
  connectionLimit: 10
});

const sessionStore = new MySQLStore({
  ...dbConfig,
  createDatabaseTable: true,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
  expiration: 24 * 60 * 60 * 1000
});

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

app.use(session({
  name: "smartspend.sid",
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

// Login page and protected dashboard
app.get("/", (req, res) => {
  res.redirect(req.session.userId ? "/app" : "/login");
});

app.get("/login", (req, res) => {
console.log("LOGIN ROUTE HIT");
  if (req.session.userId) return res.redirect("/app");
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/app", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Public health check
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "connected", database: "expense_tracker" });
  } catch (error) {
    console.error("Database health check failed:", error.message);
    res.status(503).json({ status: "database connection failed" });
  }
});

// Signup
app.post("/api/signup", authLimiter, async (req, res) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: "Name must be 2–100 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (password.length < 12 || password.length > 72) {
      return res.status(400).json({
        error: "Use a password between 12 and 72 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, passwordHash]
    );

    // Create a session after signup and rotate the session ID.
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session error:", err.message);
        return res.status(500).json({ error: "Could not create session." });
      }
      req.session.userId = result.insertId;
      req.session.userName = name;
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr.message);
          return res.status(500).json({ error: "Could not save session." });
        }
        res.status(201).json({
          message: "Account created successfully.",
          user: { id: result.insertId, name, email }
        });
      });
    });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    console.error("Signup error:", error.message);
    res.status(500).json({ error: "Signup failed. Please try again." });
  }
});

// Login
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (!email || !password || password.length > 72) {
      return res.status(400).json({ error: "Enter your email and password." });
    }

    const [rows] = await pool.execute(
      "SELECT id, name, email, password_hash FROM users WHERE email = ?",
      [email]
    );
    const user = rows[0];

    // Same message whether the email or password is wrong.
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session error:", err.message);
        return res.status(500).json({ error: "Could not create session." });
      }
      req.session.userId = user.id;
      req.session.userName = user.name;
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr.message);
          return res.status(500).json({ error: "Could not save session." });
        }
        res.json({
          message: "Login successful.",
          user: { id: user.id, name: user.name, email: user.email }
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

// Current logged-in user
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, name, email FROM users WHERE id = ?",
      [req.session.userId]
    );
    if (!rows.length) return res.status(401).json({ error: "Please log in again." });
    res.json({ user: rows[0] });
  } catch (error) {
    console.error("User lookup error:", error.message);
    res.status(500).json({ error: "Could not load account." });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err.message);
      return res.status(500).json({ error: "Logout failed." });
    }
    res.clearCookie("smartspend.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production"
    });
    res.json({ message: "Logged out successfully." });
  });
});

// Every transaction endpoint requires login and scopes data to that user.
app.get("/api/transactions", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, title, amount, type, category, transaction_date, created_at
       FROM transactions WHERE user_id = ?
       ORDER BY transaction_date DESC, id DESC`,
      [req.session.userId]
    );
    res.json(rows);
  } catch (error) {
    console.error("Fetch transactions error:", error.message);
    res.status(500).json({ error: "Failed to fetch transactions." });
  }
});

app.post("/api/transactions", requireAuth, async (req, res) => {
  try {
    const { title, amount, type, category, transaction_date } = req.body;
    const validDate = typeof transaction_date === "string" &&
      /^\d{4}-\d{2}-\d{2}$/.test(transaction_date) &&
      !Number.isNaN(Date.parse(transaction_date));

    if (typeof title !== "string" || !title.trim() || title.trim().length > 100 ||
        !Number.isFinite(Number(amount)) || Number(amount) <= 0 ||
        Number(amount) > 99999999.99 ||
        !["income", "expense"].includes(type) || !validDate) {
      return res.status(400).json({ error: "Invalid transaction details." });
    }

    const [result] = await pool.execute(
      `INSERT INTO transactions
       (user_id, title, amount, type, category, transaction_date)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        req.session.userId, title.trim(), Number(amount), type,
        typeof category === "string" && category.trim()
          ? category.trim().slice(0, 50) : "Other",
        transaction_date
      ]
    );

    res.status(201).json({ id: result.insertId, message: "Transaction saved." });
  } catch (error) {
    console.error("Save transaction error:", error.message);
    res.status(500).json({ error: "Failed to save transaction." });
  }
});

app.delete("/api/transactions/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid transaction ID." });
  }

  try {
    const [result] = await pool.execute(
      "DELETE FROM transactions WHERE id = ? AND user_id = ?",
      [id, req.session.userId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: "Transaction not found." });
    }
    res.json({ message: "Transaction deleted." });
  } catch (error) {
    console.error("Delete transaction error:", error.message);
    res.status(500).json({ error: "Failed to delete transaction." });
  }
});

// Do not expose project files, .env, or server.js through static hosting.
app.use((req, res) => {
  res.status(404).send("Not found");
});

async function start() {
  await pool.query("SELECT 1");
  await sessionStore.onReady();
  app.listen(PORT, () => {
    console.log(`SmartSpend server running at http://localhost:${PORT}`);
  });
}

start().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
