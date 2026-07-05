import { Env, User } from "./types";
import { uuid, randomHex, now } from "./utils";
import { createSession, sessionCookie } from "./session";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const OAUTH_STATE_TTL = 600; // 10 minutes

interface GoogleTokenResponse {
  id_token: string;
  access_token: string;
}

interface GoogleIdTokenPayload {
  sub: string;   // google_id
  email: string;
  name: string;
  email_verified: boolean;
}

/** GET /auth/google — redirect to Google OAuth */
export async function handleGoogleLogin(request: Request, env: Env): Promise<Response> {
  const state = await randomHex(16);
  const redirectUri = `${env.API_URL}/auth/callback`;

  // Store state in KV with 10-minute TTL instead of a cookie
  // (cross-domain cookies are unreliable across redirect flows)
  await env.SESSIONS.put(`oauth_state:${state}`, "1", { expirationTtl: OAUTH_STATE_TTL });

  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
    access_type: "online",
    prompt: "select_account",
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${GOOGLE_AUTH_URL}?${params.toString()}`,
    },
  });
}

/** GET /auth/callback — handle OAuth callback */
export async function handleGoogleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return Response.redirect(`${env.FRONTEND_URL}/?error=oauth_denied`, 302);
  }

  if (!state) {
    return Response.redirect(`${env.FRONTEND_URL}/?error=invalid_state`, 302);
  }

  // Verify state from KV (replaces cookie-based state check)
  const storedState = await env.SESSIONS.get(`oauth_state:${state}`);
  if (!storedState) {
    return Response.redirect(`${env.FRONTEND_URL}/?error=invalid_state`, 302);
  }
  // Delete state from KV immediately — single use
  await env.SESSIONS.delete(`oauth_state:${state}`);

  if (!code) {
    return Response.redirect(`${env.FRONTEND_URL}/?error=missing_code`, 302);
  }

  // Exchange code for tokens
  let profile: GoogleIdTokenPayload;
  try {
    profile = await exchangeCodeForProfile(code, env);
  } catch {
    return Response.redirect(`${env.FRONTEND_URL}/?error=token_exchange_failed`, 302);
  }

  // Upsert user in D1
  const user = await upsertUser(profile, env);

  // Create session
  const sessionId = await createSession(env.SESSIONS, user);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.FRONTEND_URL}/dashboard`,
      "Set-Cookie": sessionCookie(sessionId),
    },
  });
}

/** GET /auth/logout */
export async function handleLogout(request: Request, env: Env, sessionId: string): Promise<Response> {
  await env.SESSIONS.delete(sessionId);
  return new Response(null, {
    status: 302,
    headers: {
      Location: env.FRONTEND_URL,
      "Set-Cookie": sessionCookie("", true),
    },
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function exchangeCodeForProfile(
  code: string,
  env: Env
): Promise<GoogleIdTokenPayload> {
  const resp = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${env.API_URL}/auth/callback`,
      grant_type: "authorization_code",
    }),
  });

  if (!resp.ok) {
    throw new Error(`Google token exchange failed: ${resp.status}`);
  }

  const tokens = (await resp.json()) as GoogleTokenResponse;

  // Decode JWT payload (we trust Google's signature — no verification needed
  // since we just received it directly from Google's token endpoint over HTTPS)
  const parts = tokens.id_token.split(".");
  if (parts.length !== 3) throw new Error("Invalid id_token format");
  const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
  return payload as GoogleIdTokenPayload;
}

async function upsertUser(profile: GoogleIdTokenPayload, env: Env): Promise<User> {
  const { sub: google_id, email, name } = profile;

  // Check if first user = auto-promote to admin if email matches ADMIN_GOOGLE_EMAIL
  const isAdmin = email === env.ADMIN_GOOGLE_EMAIL ? 1 : 0;

  // Upsert: insert or update name/email on conflict
  const existing = await env.DB.prepare(
    "SELECT * FROM users WHERE google_id = ?"
  )
    .bind(google_id)
    .first<User>();

  if (existing) {
    // Update name/email in case they changed in Google
    await env.DB.prepare(
      "UPDATE users SET email = ?, name = ? WHERE id = ?"
    )
      .bind(email, name, existing.id)
      .run();

    // Ensure admin status for the configured admin email
    if (isAdmin && !existing.is_admin) {
      await env.DB.prepare("UPDATE users SET is_admin = 1 WHERE id = ?")
        .bind(existing.id)
        .run();
    }

    return { ...existing, email, name, is_admin: existing.is_admin || isAdmin };
  }

  const id = uuid();
  const created_at = now();
  const slotCount = isAdmin ? 9999 : 1;

  await env.DB.prepare(
    "INSERT INTO users (id, google_id, email, name, is_admin, slot_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(id, google_id, email, name, isAdmin, slotCount, created_at)
    .run();

  return { id, google_id, email, name, is_admin: isAdmin, slot_count: slotCount, created_at };
}
