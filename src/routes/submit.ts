import { Env, Website, User } from "../types";
import { sha256, json, getIP, isValidDomain } from "../utils";
import { sendFormEmail } from "../email";
import { submitCorsHeaders, handleSubmitPreflight } from "../cors";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_NAME = 255;
const MAX_MESSAGE = 5000;
const MAX_SUBJECT = 255;

export async function handleSubmit(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");

  // Preflight
  if (request.method === "OPTIONS") {
    return handleSubmitPreflight(origin);
  }

  if (request.method !== "POST") {
    return json({ success: false, message: "Method not allowed" }, 405, submitCorsHeaders(origin));
  }

  const cors = submitCorsHeaders(origin);

  // ── 1. Parse body ──────────────────────────────────────────────────────────
  let body: Record<string, string>;
  try {
    const contentType = request.headers.get("Content-Type") ?? "";
    if (contentType.includes("application/json")) {
      body = await request.json() as Record<string, string>;
    } else {
      const fd = await request.formData();
      body = Object.fromEntries(
        [...fd.entries()].map(([k, v]) => [k, String(v)])
      );
    }
  } catch {
    return json({ success: false, message: "Invalid request body" }, 400, cors);
  }

  const { api_key, name, email, message, subject, ...extraFields } = body;

  // ── 2. API key presence ────────────────────────────────────────────────────
  if (!api_key) {
    return json({ success: false, message: "Unauthorized: Missing API key." }, 401, cors);
  }

  // ── 3. Hash key and look up website ───────────────────────────────────────
  const keyHash = await sha256(api_key);
  const website = await env.DB.prepare(
    "SELECT w.*, u.email as owner_email FROM websites w JOIN users u ON u.id = w.user_id WHERE w.api_key_hash = ?"
  )
    .bind(keyHash)
    .first<Website & { owner_email: string }>();

  if (!website) {
    return json({ success: false, message: "Unauthorized: Invalid API key." }, 401, cors);
  }

  // ── 4. Origin check ────────────────────────────────────────────────────────
  if (origin) {
    let originHost: string;
    try {
      originHost = new URL(origin).hostname;
    } catch {
      return json({ success: false, message: "Forbidden: Invalid origin." }, 403, cors);
    }
    if (originHost !== website.domain) {
      return json({ success: false, message: "Forbidden: Origin not allowed." }, 403, cors);
    }
  }
  // If no Origin header (e.g. server-side POST) — allow through

  // ── 5. Rate limiting via Durable Object ───────────────────────────────────
  const ip = getIP(request);
  const doId = env.RATE_LIMITER.idFromName(ip);
  const limiter = env.RATE_LIMITER.get(doId);
  const limitRes = await limiter.fetch(new Request("https://internal/check"));
  if (limitRes.status === 429) {
    return json(
      { success: false, message: "Too many requests. Please wait 10 minutes." },
      429,
      cors
    );
  }

  // ── 6. Required field validation ──────────────────────────────────────────
  if (!name || !email || !message) {
    return json(
      { success: false, message: "Missing required fields: name, email, message." },
      400,
      cors
    );
  }

  // Field length limits
  if (name.length > MAX_NAME) {
    return json({ success: false, message: `Name must be under ${MAX_NAME} characters.` }, 400, cors);
  }
  if (message.length > MAX_MESSAGE) {
    return json({ success: false, message: `Message must be under ${MAX_MESSAGE} characters.` }, 400, cors);
  }
  if (subject && subject.length > MAX_SUBJECT) {
    return json({ success: false, message: `Subject must be under ${MAX_SUBJECT} characters.` }, 400, cors);
  }

  // ── 7. Email format validation ─────────────────────────────────────────────
  if (!EMAIL_RE.test(email)) {
    return json({ success: false, message: "Invalid sender email format." }, 400, cors);
  }

  // ── 8. Send email ──────────────────────────────────────────────────────────
  const emailSubject = subject?.trim() || `New form submission from ${name}`;
  // Remove reserved fields from extras — only pass through unknown custom fields
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { api_key: _ak, name: _n, email: _e, message: _m, subject: _s, ...safeExtras } = body;

  try {
    await sendFormEmail(env, {
      to: website.owner_email,
      replyTo: email,
      subject: emailSubject,
      name,
      email,
      message,
      extraFields: safeExtras,
    });
  } catch (err) {
    console.error("Email send error:", err);
    return json(
      { success: false, message: "Failed to send email. Please try again later." },
      500,
      cors
    );
  }

  return json({ success: true, message: "Message sent successfully." }, 200, cors);
}
