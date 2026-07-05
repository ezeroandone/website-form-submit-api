import { Env, Session, User } from "./types";
import { randomHex } from "./utils";

const SESSION_COOKIE = "fs_session";
const SESSION_TTL = 604800; // 7 days in seconds

/** Create a new session in KV and return the session ID */
export async function createSession(
  kv: KVNamespace,
  user: User
): Promise<string> {
  const sessionId = await randomHex(32);
  const session: Session = {
    user_id: user.id,
    is_admin: user.is_admin === 1,
  };
  await kv.put(sessionId, JSON.stringify(session), {
    expirationTtl: SESSION_TTL,
  });
  return sessionId;
}

/** Retrieve and parse a session from KV. Returns null if missing/expired. */
export async function getSession(
  kv: KVNamespace,
  sessionId: string
): Promise<Session | null> {
  const raw = await kv.get(sessionId);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

/** Delete a session from KV */
export async function deleteSession(
  kv: KVNamespace,
  sessionId: string
): Promise<void> {
  await kv.delete(sessionId);
}

/** Build Set-Cookie header value for the session cookie */
export function sessionCookie(sessionId: string, clear = false): string {
  if (clear) {
    return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Domain=.ezeroandone.io; Max-Age=0`;
  }
  return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=None; Domain=.ezeroandone.io; Max-Age=${SESSION_TTL}`;
}

/** Extract the session ID from the Cookie header */
export function extractSessionId(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  if (!match) return null;
  return match.slice(SESSION_COOKIE.length + 1) || null;
}
