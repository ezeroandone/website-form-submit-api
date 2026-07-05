/** Generate a cryptographically random UUID v4 */
export function uuid(): string {
  return crypto.randomUUID();
}

/** Generate a random hex string of `bytes` bytes */
export async function randomHex(bytes: number): Promise<string> {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 hash → hex string */
export async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** HMAC-SHA512 → hex string (used for Paystack webhook verification) */
export async function hmacSha512(secret: string, data: string): Promise<string> {
  const keyData = new TextEncoder().encode(secret);
  const msgData = new TextEncoder().encode(data);
  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgData);
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Timing-safe string comparison */
export function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

/** Parse cookies from a Cookie header string */
export function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(
    header.split(";").map((c) => {
      const [k, ...v] = c.trim().split("=");
      return [k.trim(), decodeURIComponent(v.join("="))];
    })
  );
}

/** ISO-8601 timestamp */
export function now(): string {
  return new Date().toISOString();
}

/** Validate a domain hostname — no protocol, path, or query string */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  // Must not contain protocol, path, or query
  if (domain.includes("/") || domain.includes("?") || domain.includes("#")) return false;
  if (domain.includes("://")) return false;
  // Basic hostname regex: labels separated by dots
  const hostnameRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return hostnameRe.test(domain);
}

/** Build a JSON response */
export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

/** Extract IP from request (CF provides CF-Connecting-IP) */
export function getIP(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}
