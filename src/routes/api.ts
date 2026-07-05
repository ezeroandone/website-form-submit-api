import { Env, Website } from "../types";
import { AuthContext } from "../middleware";
import { uuid, sha256, randomHex, now, json, isValidDomain } from "../utils";
import { authCorsHeaders } from "../cors";
import { Resend } from "resend";

const cors = authCorsHeaders();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ─── GET /api/me ──────────────────────────────────────────────────────────────
export async function handleMe(ctx: AuthContext, env: Env): Promise<Response> {
  const { user } = ctx;
  const countResult = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM websites WHERE user_id = ?"
  )
    .bind(user.id)
    .first<{ cnt: number }>();

  return json(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      is_admin: user.is_admin === 1,
      slot_count: user.slot_count,
      website_count: countResult?.cnt ?? 0,
    },
    200,
    cors
  );
}

// ─── GET /api/websites ────────────────────────────────────────────────────────
export async function handleListWebsites(ctx: AuthContext, env: Env): Promise<Response> {
  const { user } = ctx;
  const { results } = await env.DB.prepare(
    "SELECT id, domain, notify_email, email_verified, created_at FROM websites WHERE user_id = ? ORDER BY created_at DESC"
  )
    .bind(user.id)
    .all<{ id: string; domain: string; notify_email: string; email_verified: number; created_at: string }>();

  return json(results ?? [], 200, cors);
}

// ─── POST /api/websites ───────────────────────────────────────────────────────
export async function handleCreateWebsite(
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  let body: { domain?: string; notify_email?: string };
  try {
    body = await request.json() as { domain?: string; notify_email?: string };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  const domain = body.domain?.trim().toLowerCase();
  if (!domain || !isValidDomain(domain)) {
    return json({ error: "Invalid domain. Provide a hostname like example.com" }, 400, cors);
  }

  const notify_email = body.notify_email?.trim().toLowerCase();
  if (!notify_email || !EMAIL_RE.test(notify_email)) {
    return json({ error: "A valid notification email is required." }, 400, cors);
  }

  // Slot check
  const countResult = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM websites WHERE user_id = ?"
  )
    .bind(user.id)
    .first<{ cnt: number }>();

  if ((countResult?.cnt ?? 0) >= user.slot_count) {
    return json({ error: "Website slot limit reached. Please upgrade your plan." }, 403, cors);
  }

  // Duplicate domain check
  const existing = await env.DB.prepare(
    "SELECT id FROM websites WHERE user_id = ? AND domain = ?"
  )
    .bind(user.id, domain)
    .first();
  if (existing) {
    return json({ error: "You have already registered this domain." }, 409, cors);
  }

  // Generate API key
  const rawKey = await randomHex(32);
  const keyHash = await sha256(rawKey);
  const verifyToken = await randomHex(32);
  const websiteId = uuid();
  const created_at = now();

  await env.DB.prepare(
    "INSERT INTO websites (id, user_id, domain, api_key_hash, notify_email, email_verified, verify_token, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)"
  )
    .bind(websiteId, user.id, domain, keyHash, notify_email, verifyToken, created_at)
    .run();

  // Send verification email
  await sendVerificationEmail(env, notify_email, domain, verifyToken);

  return json(
    {
      website_id: websiteId,
      domain,
      notify_email,
      email_verified: false,
      created_at,
      api_key: rawKey,
    },
    201,
    cors
  );
}

// ─── POST /api/websites/resend-verification ───────────────────────────────────
export async function handleResendVerification(
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  let body: { website_id?: string };
  try {
    body = await request.json() as { website_id?: string };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  if (!body.website_id) {
    return json({ error: "Missing website_id" }, 400, cors);
  }

  const website = await env.DB.prepare(
    "SELECT id, user_id, domain, notify_email, email_verified FROM websites WHERE id = ?"
  )
    .bind(body.website_id)
    .first<Pick<Website, "id" | "user_id" | "domain" | "notify_email" | "email_verified">>();

  if (!website || website.user_id !== user.id) {
    return json({ error: "Website not found" }, 404, cors);
  }

  if (website.email_verified) {
    return json({ error: "Email is already verified." }, 400, cors);
  }

  // Generate a fresh token
  const verifyToken = await randomHex(32);
  await env.DB.prepare("UPDATE websites SET verify_token = ? WHERE id = ?")
    .bind(verifyToken, website.id)
    .run();

  await sendVerificationEmail(env, website.notify_email, website.domain, verifyToken);

  return json({ success: true, message: "Verification email resent." }, 200, cors);
}

// ─── GET /api/verify-email?token=... (public route, no auth) ─────────────────
export async function handleVerifyEmail(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");

  if (!token) {
    return new Response("Missing token.", { status: 400 });
  }

  const website = await env.DB.prepare(
    "SELECT id, email_verified FROM websites WHERE verify_token = ?"
  )
    .bind(token)
    .first<{ id: string; email_verified: number }>();

  if (!website) {
    return new Response(verifyHtml("Invalid or expired verification link.", false), {
      status: 400,
      headers: { "Content-Type": "text/html" },
    });
  }

  if (website.email_verified) {
    return new Response(verifyHtml("This email is already verified.", true), {
      status: 200,
      headers: { "Content-Type": "text/html" },
    });
  }

  await env.DB.prepare(
    "UPDATE websites SET email_verified = 1, verify_token = NULL WHERE id = ?"
  )
    .bind(website.id)
    .run();

  return new Response(verifyHtml("Email verified! Your website is now active.", true), {
    status: 200,
    headers: { "Content-Type": "text/html" },
  });
}

// ─── DELETE /api/websites/:id ─────────────────────────────────────────────────
export async function handleDeleteWebsite(
  websiteId: string,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  const website = await env.DB.prepare(
    "SELECT id, user_id FROM websites WHERE id = ?"
  )
    .bind(websiteId)
    .first<{ id: string; user_id: string }>();

  if (!website || website.user_id !== user.id) {
    return json({ error: "Website not found" }, 404, cors);
  }

  await env.DB.prepare("DELETE FROM websites WHERE id = ?").bind(websiteId).run();
  return json({ success: true }, 200, cors);
}

// ─── POST /api/keys/rotate ────────────────────────────────────────────────────
export async function handleRotateKey(
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  let body: { website_id?: string };
  try {
    body = await request.json() as { website_id?: string };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  if (!body.website_id) {
    return json({ error: "Missing required field: website_id" }, 400, cors);
  }

  const website = await env.DB.prepare(
    "SELECT id, user_id FROM websites WHERE id = ?"
  )
    .bind(body.website_id)
    .first<{ id: string; user_id: string }>();

  if (!website || website.user_id !== user.id) {
    return json({ error: "Website not found" }, 404, cors);
  }

  const newRawKey = await randomHex(32);
  const newHash = await sha256(newRawKey);

  const result = await env.DB.prepare(
    "UPDATE websites SET api_key_hash = ? WHERE id = ?"
  )
    .bind(newHash, body.website_id)
    .run();

  if (!result.success) {
    return json({ error: "Failed to rotate key. Please try again." }, 500, cors);
  }

  return json({ api_key: newRawKey }, 200, cors);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
async function sendVerificationEmail(
  env: Env,
  to: string,
  domain: string,
  token: string
): Promise<void> {
  const verifyUrl = `${env.API_URL}/api/verify-email?token=${token}`;
  const resend = new Resend(env.RESEND_API_KEY);
  await resend.emails.send({
    from: env.FROM_EMAIL,
    to,
    subject: `Verify your email for ${domain} on FormSend`,
    html: `
      <div style="font-family:sans-serif;max-width:500px;margin:auto;padding:24px">
        <div style="border-left:4px solid #C5A059;padding-left:16px;margin-bottom:24px">
          <h2 style="margin:0;color:#C5A059">Verify your email</h2>
        </div>
        <p>You registered <strong>${domain}</strong> on FormSend. Click the button below to verify this email address and activate your website.</p>
        <a href="${verifyUrl}" style="display:inline-block;margin:24px 0;background:#C5A059;color:#000;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none">
          Verify email address
        </a>
        <p style="font-size:12px;color:#999">This link expires after use. If you did not register on FormSend, ignore this email.</p>
        <p style="font-size:12px;color:#999">Or copy this URL: ${verifyUrl}</p>
      </div>
    `,
  });
}

function verifyHtml(message: string, success: boolean): string {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0f0f0f;color:#f0f0f0">
    <div style="text-align:center;padding:2rem">
      <div style="font-size:3rem;margin-bottom:1rem">${success ? "✅" : "❌"}</div>
      <h2 style="color:${success ? "#4caf82" : "#e05252"}">${message}</h2>
      <a href="https://formsend.ezeroandone.io/dashboard" style="display:inline-block;margin-top:1.5rem;background:#C5A059;color:#000;font-weight:700;padding:10px 20px;border-radius:8px;text-decoration:none">
        Go to dashboard
      </a>
    </div>
  </body></html>`;
}
