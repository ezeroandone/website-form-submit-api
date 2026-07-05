import { Env } from "../types";
import { AuthContext } from "../middleware";
import { uuid, hmacSha512, safeCompare, now, json } from "../utils";
import { authCorsHeaders } from "../cors";

const cors = authCorsHeaders();

// Paystack: $1 USD → 100 kobo (Paystack uses USD for international accounts)
// Adjust currency/multiplier if your account is NGN-based
const PLANS: Record<number, { slot_increment: number; amount_kobo: number }> = {
  1: { slot_increment: 5, amount_kobo: 100 },   // $1 → 5 sites
  5: { slot_increment: 50, amount_kobo: 500 },  // $5 → 50 sites
};

// ─── POST /api/payment/initiate ───────────────────────────────────────────────
export async function handlePaymentInitiate(
  request: Request,
  ctx: AuthContext,
  env: Env
): Promise<Response> {
  const { user } = ctx;

  let body: { amount?: number };
  try {
    body = await request.json() as { amount?: number };
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }

  const amount = Number(body.amount);
  const plan = PLANS[amount];

  if (!plan) {
    return json(
      { error: "Invalid payment amount. Accepted values: 1, 5 (USD)." },
      400,
      cors
    );
  }

  // Call Paystack initialize transaction API
  const paystackRes = await fetch("https://api.paystack.co/transaction/initialize", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: user.email,
      amount: plan.amount_kobo,
      currency: "USD",
      metadata: {
        user_id: user.id,
        slot_increment: plan.slot_increment,
      },
    }),
  });

  if (!paystackRes.ok) {
    console.error("Paystack init failed:", await paystackRes.text());
    return json({ error: "Payment service unavailable. Please try again." }, 502, cors);
  }

  const paystackData = (await paystackRes.json()) as {
    status: boolean;
    data: { authorization_url: string; reference: string };
  };

  if (!paystackData.status || !paystackData.data?.authorization_url) {
    return json({ error: "Failed to create payment session." }, 502, cors);
  }

  return json({ authorization_url: paystackData.data.authorization_url }, 200, cors);
}

// ─── POST /api/payment/webhook ────────────────────────────────────────────────
// This route must NOT require session auth — Paystack calls it directly
export async function handlePaymentWebhook(
  request: Request,
  env: Env
): Promise<Response> {
  // Read raw body for signature verification
  const rawBody = await request.text();
  const signature = request.headers.get("x-paystack-signature") ?? "";

  // Verify HMAC-SHA512 signature
  const expectedSig = await hmacSha512(env.PAYSTACK_SECRET_KEY, rawBody);
  if (!safeCompare(expectedSig, signature)) {
    return json({ error: "Invalid signature" }, 400);
  }

  let event: {
    event: string;
    data: {
      reference: string;
      amount: number;
      metadata: { user_id: string; slot_increment: number };
    };
  };

  try {
    event = JSON.parse(rawBody);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  // Only process successful charges
  if (event.event !== "charge.success") {
    return json({ received: true }, 200);
  }

  const { reference, amount, metadata } = event.data;
  const { user_id, slot_increment } = metadata ?? {};

  // Validate metadata
  if (!user_id || !slot_increment || slot_increment <= 0) {
    console.error("Webhook: invalid metadata", metadata);
    return json({ error: "Invalid metadata" }, 400);
  }

  // Idempotency — skip if we've already processed this reference
  const existing = await env.DB.prepare(
    "SELECT id FROM payments WHERE paystack_reference = ?"
  )
    .bind(reference)
    .first();

  if (existing) {
    // Already processed — acknowledge silently
    return json({ received: true }, 200);
  }

  // Check user exists
  const user = await env.DB.prepare("SELECT id FROM users WHERE id = ?")
    .bind(user_id)
    .first<{ id: string }>();

  if (!user) {
    console.error("Webhook: user not found", user_id);
    return json({ error: "User not found" }, 400);
  }

  // Atomically update slot_count and insert payment record
  const paymentId = uuid();
  const created_at = now();

  try {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE users SET slot_count = slot_count + ? WHERE id = ?"
      ).bind(slot_increment, user_id),
      env.DB.prepare(
        "INSERT INTO payments (id, user_id, amount, slot_increment, paystack_reference, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(paymentId, user_id, amount, slot_increment, reference, created_at),
    ]);
  } catch (err) {
    console.error("Webhook: DB error", err);
    return json({ error: "Database error" }, 500);
  }

  return json({ received: true }, 200);
}
