import { Env, Session, User } from "./types";
import { extractSessionId, getSession } from "./session";
import { json } from "./utils";
import { authCorsHeaders } from "./cors";

export interface AuthContext {
  session: Session;
  user: User;
}

/**
 * Authenticate a request. Returns an AuthContext on success,
 * or a Response (401) on failure.
 */
export async function authenticate(
  request: Request,
  env: Env
): Promise<AuthContext | Response> {
  const cookieHeader = request.headers.get("Cookie");
  const sessionId = extractSessionId(cookieHeader);

  if (!sessionId) {
    return json({ error: "Unauthorized" }, 401, authCorsHeaders());
  }

  const session = await getSession(env.SESSIONS, sessionId);
  if (!session) {
    return json({ error: "Unauthorized" }, 401, authCorsHeaders());
  }

  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?")
    .bind(session.user_id)
    .first<User>();

  if (!user) {
    return json({ error: "Unauthorized" }, 401, authCorsHeaders());
  }

  return { session, user };
}

/**
 * Require admin. Returns 403 if not admin.
 */
export function requireAdmin(ctx: AuthContext): Response | null {
  if (!ctx.user.is_admin) {
    return json({ error: "Forbidden" }, 403, authCorsHeaders());
  }
  return null;
}
