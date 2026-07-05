import { Env } from "./types";
import { json } from "./utils";
import { enforceAuthCors, handleAuthPreflight, authCorsHeaders } from "./cors";
import { authenticate, requireAdmin } from "./middleware";
import { handleGoogleLogin, handleGoogleCallback, handleLogout } from "./auth";
import { handleSubmit } from "./routes/submit";
import { handleMe, handleListWebsites, handleCreateWebsite, handleDeleteWebsite, handleRotateKey } from "./routes/api";
import { handlePaymentInitiate, handlePaymentWebhook } from "./routes/payments";
import { handleAdminListUsers, handleAdminUpdateUser } from "./routes/admin";

// Re-export Durable Object class so Wrangler can register it
export { RateLimiter } from "./ratelimiter";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ── Health checks (public) ───────────────────────────────────────────────
    if (path === "/" && method === "GET") {
      return json({ status: "Form API is running.", version: "2.0.0" });
    }
    if (path === "/health" && method === "GET") {
      return json({ status: "ok" });
    }

    // ── Form submission (public, any origin) ─────────────────────────────────
    if (path === "/submit") {
      return handleSubmit(request, env);
    }

    // ── Auth routes ──────────────────────────────────────────────────────────
    if (path.startsWith("/auth/")) {
      if (method === "OPTIONS") return handleAuthPreflight();

      if (path === "/auth/google" && method === "GET") {
        return handleGoogleLogin(request, env);
      }

      if (path === "/auth/callback" && method === "GET") {
        return handleGoogleCallback(request, env);
      }

      if (path === "/auth/logout" && method === "POST") {
        const corsCheck = enforceAuthCors(request);
        if (corsCheck) return corsCheck;
        const authResult = await authenticate(request, env);
        if (authResult instanceof Response) return authResult;
        const cookieHeader = request.headers.get("Cookie") ?? "";
        const sessionId = cookieHeader
          .split(";")
          .map((c) => c.trim())
          .find((c) => c.startsWith("fs_session="))
          ?.slice("fs_session=".length);
        if (sessionId) await env.SESSIONS.delete(sessionId);
        return new Response(null, {
          status: 302,
          headers: { Location: env.FRONTEND_URL, "Set-Cookie": "fs_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" },
        });
      }

      return json({ error: "Not found" }, 404);
    }

    // ── Webhook (no session auth — Paystack calls this directly) ─────────────
    if (path === "/api/payment/webhook" && method === "POST") {
      return handlePaymentWebhook(request, env);
    }

    // ── Authenticated API routes ─────────────────────────────────────────────
    if (path.startsWith("/api/")) {
      if (method === "OPTIONS") return handleAuthPreflight();

      // CORS check for all /api/* routes
      const corsCheck = enforceAuthCors(request);
      if (corsCheck) return corsCheck;

      // Auth check
      const authResult = await authenticate(request, env);
      if (authResult instanceof Response) return authResult;
      const ctx = authResult;

      // ── User profile
      if (path === "/api/me" && method === "GET") {
        return handleMe(ctx, env);
      }

      // ── Websites
      if (path === "/api/websites" && method === "GET") {
        return handleListWebsites(ctx, env);
      }
      if (path === "/api/websites" && method === "POST") {
        return handleCreateWebsite(request, ctx, env);
      }
      const websiteDeleteMatch = path.match(/^\/api\/websites\/([^/]+)$/);
      if (websiteDeleteMatch && method === "DELETE") {
        return handleDeleteWebsite(websiteDeleteMatch[1], ctx, env);
      }

      // ── Key rotation
      if (path === "/api/keys/rotate" && method === "POST") {
        return handleRotateKey(request, ctx, env);
      }

      // ── Payments
      if (path === "/api/payment/initiate" && method === "POST") {
        return handlePaymentInitiate(request, ctx, env);
      }

      // ── Admin
      if (path === "/api/admin/users" && method === "GET") {
        const adminCheck = requireAdmin(ctx);
        if (adminCheck) return adminCheck;
        return handleAdminListUsers(ctx, env);
      }
      const adminUserMatch = path.match(/^\/api\/admin\/users\/([^/]+)$/);
      if (adminUserMatch && method === "PATCH") {
        const adminCheck = requireAdmin(ctx);
        if (adminCheck) return adminCheck;
        return handleAdminUpdateUser(adminUserMatch[1], request, ctx, env);
      }

      return json({ error: "Not found" }, 404, authCorsHeaders());
    }

    return json({ error: "Not found" }, 404);
  },
};
