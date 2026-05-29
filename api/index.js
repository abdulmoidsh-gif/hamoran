const express = require("express");
const app = express();

app.use(express.json());

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Hamoran API running" });
});

// Simple login test route (placeholder)
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (email === "admin@hamoran.com" && password === "admin") {
    return res.json({ success: true, role: "admin" });
  }

  return res.status(401).json({ success: false, message: "Invalid credentials" });
});

module.exports = app;
