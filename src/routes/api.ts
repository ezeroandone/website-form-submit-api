import { Env, Website } from "../types";
import { AuthContext } from "../middleware";
import { uuid, sha256, randomHex, now, json, isValidDomain } from "../utils";
import { authCorsHeaders } from "../cors";

const cors = authCorsHeaders();

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
    "SELECT id, domain, created_at FROM websites WHERE user_id = ? ORDER BY created_at DESC"
  )
    .bind(user.id)
    .all<{ id: string; domain: string; created_at: string }>();

  return json(results ?? [], 200, cors);
}

// ─── POST /api/websites ───────────────────────────────────────────────────────
export async function handleCreateWebsite(
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  let body: { domain?: string };
  try {
    body = await request.json() as { domain?: string };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  const domain = body.domain?.trim().toLowerCase();
  if (!domain || !isValidDomain(domain)) {
    return json({ error: "Invalid domain. Provide a hostname like example.com" }, 400, cors);
  }

  // Slot check (admins have effectively unlimited slots via large slot_count)
  const countResult = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM websites WHERE user_id = ?"
  )
    .bind(user.id)
    .first<{ cnt: number }>();
  const count = countResult?.cnt ?? 0;

  if (count >= user.slot_count) {
    return json(
      { error: "Website slot limit reached. Please upgrade your plan." },
      403,
      cors
    );
  }

  // Duplicate domain check for this user
  const existing = await env.DB.prepare(
    "SELECT id FROM websites WHERE user_id = ? AND domain = ?"
  )
    .bind(user.id, domain)
    .first();
  if (existing) {
    return json({ error: "You have already registered this domain." }, 409, cors);
  }

  // Generate API key — raw key shown once, store hash
  const rawKey = await randomHex(32);
  const keyHash = await sha256(rawKey);

  const websiteId = uuid();
  const created_at = now();

  await env.DB.prepare(
    "INSERT INTO websites (id, user_id, domain, api_key_hash, created_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(websiteId, user.id, domain, keyHash, created_at)
    .run();

  return json(
    {
      website_id: websiteId,
      domain,
      created_at,
      api_key: rawKey, // shown exactly once
    },
    201,
    cors
  );
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

  const { website_id } = body;
  if (!website_id) {
    return json({ error: "Missing required field: website_id" }, 400, cors);
  }

  const website = await env.DB.prepare(
    "SELECT id, user_id FROM websites WHERE id = ?"
  )
    .bind(website_id)
    .first<{ id: string; user_id: string }>();

  if (!website || website.user_id !== user.id) {
    return json({ error: "Website not found" }, 404, cors);
  }

  const newRawKey = await randomHex(32);
  const newHash = await sha256(newRawKey);

  const result = await env.DB.prepare(
    "UPDATE websites SET api_key_hash = ? WHERE id = ?"
  )
    .bind(newHash, website_id)
    .run();

  if (!result.success) {
    return json({ error: "Failed to rotate key. Please try again." }, 500, cors);
  }

  return json({ api_key: newRawKey }, 200, cors); // shown exactly once
}
