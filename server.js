require("dotenv").config();
const express = require("express");
const { Resend } = require("resend");
const cors = require("cors");
const { RateLimiterMemory } = require("rate-limiter-flexible");

const app = express();
const PORT = process.env.PORT || 3000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── Rate Limiter: max 5 submissions per IP per 10 minutes ───────────────────
const rateLimiter = new RateLimiterMemory({
  points: 5,
  duration: 600,
});

// ─── CORS: allow only your whitelisted domains ────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
  : [];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error(`CORS: Origin ${origin} not allowed`));
    },
    methods: ["POST", "GET"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "Form API is running.", version: "1.1.0" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ─── POST /submit ─────────────────────────────────────────────────────────────
app.post("/submit", async (req, res) => {
  // 1. Rate limit check
  try {
    await rateLimiter.consume(req.ip);
  } catch {
    return res.status(429).json({ success: false, message: "Too many requests. Please wait a few minutes." });
  }

  // 2. API key validation
  const { api_key, to_email, subject, name, email, message, ...extraFields } = req.body;

  if (!api_key || api_key !== process.env.API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized: Invalid API key." });
  }

  // 3. Required field validation
  if (!to_email || !name || !email || !message) {
    return res.status(400).json({ success: false, message: "Missing required fields: to_email, name, email, message." });
  }

  // 4. Basic email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: "Invalid sender email format." });
  }

  // 5. Send via Resend
  try {
    await resend.emails.send({
      from: process.env.FROM_EMAIL || "Form API <onboarding@resend.dev>",
      to: to_email,
      reply_to: email,
      subject: subject || `New form submission from ${name}`,
      html: buildHtmlEmail(name, email, message, extraFields, subject),
    });

    return res.status(200).json({ success: true, message: "Message sent successfully." });
  } catch (err) {
    console.error("Mail send error:", err);
    return res.status(500).json({ success: false, message: "Failed to send email. Please try again later." });
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, " ");
}

function buildHtmlEmail(name, email, message, extras, subject) {
  const extraRows = Object.entries(extras)
    .filter(([, v]) => v)
    .map(
      ([k, v]) => `
      <tr>
        <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;width:140px;border-bottom:1px solid #eee;">${capitalize(k)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;">${v}</td>
      </tr>`
    )
    .join("");

  return `
    <!DOCTYPE html>
    <html>
    <body style="font-family:sans-serif;color:#333;max-width:600px;margin:auto;padding:20px;">
      <div style="border-left:4px solid #C5A059;padding-left:16px;margin-bottom:24px;">
        <h2 style="margin:0;color:#C5A059;">${subject || "New Form Submission"}</h2>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:15px;">
        <tr>
          <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;width:140px;border-bottom:1px solid #eee;">Name</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;">${name}</td>
        </tr>
        <tr>
          <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;border-bottom:1px solid #eee;">Reply To</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;"><a href="mailto:${email}">${email}</a></td>
        </tr>
        ${extraRows}
        <tr>
          <td style="padding:8px 12px;background:#f9f9f9;font-weight:600;vertical-align:top;border-bottom:1px solid #eee;">Message</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;white-space:pre-line;">${message}</td>
        </tr>
      </table>
      <p style="margin-top:24px;font-size:12px;color:#999;">Sent via your self-hosted Form Submission API.</p>
    </body>
    </html>
  `;
}

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Form API running on port ${PORT}`);
});
