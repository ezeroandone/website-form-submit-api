import { Env } from "./types";
import { json } from "./utils";

const DASHBOARD_ORIGIN = "https://formsend.ezeroandone.io";

/**
 * Returns CORS headers for authenticated API/auth routes.
 * Only allows the Dashboard origin.
 */
export function authCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": DASHBOARD_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Cookie",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
}

/**
 * Returns CORS headers for /submit (open to all origins).
 */
export function submitCorsHeaders(origin: string | null): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin ?? "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

/**
 * Middleware: enforce that the request Origin matches the Dashboard.
 * Returns a Response if the check fails, otherwise null.
 */
export function enforceAuthCors(request: Request): Response | null {
  const origin = request.headers.get("Origin");
  // Allow requests with no Origin (e.g. server-side calls, Wrangler dev)
  if (!origin) return null;
  if (origin !== DASHBOARD_ORIGIN) {
    return json({ error: "Forbidden" }, 403, {
      "Access-Control-Allow-Origin": DASHBOARD_ORIGIN,
    });
  }
  return null;
}

/**
 * Handle OPTIONS preflight for auth/api routes.
 */
export function handleAuthPreflight(): Response {
  return new Response(null, { status: 204, headers: authCorsHeaders() });
}

/**
 * Handle OPTIONS preflight for /submit.
 */
export function handleSubmitPreflight(origin: string | null): Response {
  return new Response(null, { status: 204, headers: submitCorsHeaders(origin) });
}
