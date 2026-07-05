import { Env, User } from "../types";
import { AuthContext } from "../middleware";
import { json } from "../utils";
import { authCorsHeaders } from "../cors";

const cors = authCorsHeaders();

// ─── GET /api/admin/users ─────────────────────────────────────────────────────
export async function handleAdminListUsers(
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT id, email, name, is_admin, slot_count, created_at FROM users ORDER BY created_at DESC"
  ).all<User>();

  return json(results ?? [], 200, cors);
}

// ─── PATCH /api/admin/users/:id ───────────────────────────────────────────────
export async function handleAdminUpdateUser(
  userId: string,
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  let body: { is_admin?: boolean; slot_count?: number };
  try {
    body = await request.json() as { is_admin?: boolean; slot_count?: number };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  const updates: string[] = [];
  const values: (number | string)[] = [];

  if (body.is_admin !== undefined) {
    updates.push("is_admin = ?");
    values.push(body.is_admin ? 1 : 0);
  }

  if (body.slot_count !== undefined) {
    if (!Number.isInteger(body.slot_count) || body.slot_count < 1) {
      return json({ error: "slot_count must be an integer ≥ 1" }, 400, cors);
    }
    updates.push("slot_count = ?");
    values.push(body.slot_count);
  }

  if (updates.length === 0) {
    return json({ error: "No valid fields to update (accepted: is_admin, slot_count)" }, 400, cors);
  }

  // Check user exists
  const existing = await env.DB.prepare("SELECT id FROM users WHERE id = ?")
    .bind(userId)
    .first<{ id: string }>();

  if (!existing) {
    return json({ error: "User not found" }, 404, cors);
  }

  values.push(userId);
  await env.DB.prepare(
    `UPDATE users SET ${updates.join(", ")} WHERE id = ?`
  )
    .bind(...values)
    .run();

  const updated = await env.DB.prepare(
    "SELECT id, email, name, is_admin, slot_count, created_at FROM users WHERE id = ?"
  )
    .bind(userId)
    .first<User>();

  return json(updated, 200, cors);
}
