export interface Env {
  // D1 database
  DB: D1Database;
  // KV for sessions
  SESSIONS: KVNamespace;
  // Durable Object for rate limiting
  RATE_LIMITER: DurableObjectNamespace;
  // Secrets (set via: wrangler secret put)
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  RESEND_API_KEY: string;
  FROM_EMAIL: string;
  PAYSTACK_SECRET_KEY: string;
  ADMIN_GOOGLE_EMAIL: string;
  // Vars (set in wrangler.toml)
  FRONTEND_URL: string;
  API_URL: string;
}

export interface User {
  id: string;
  google_id: string;
  email: string;
  name: string;
  is_admin: number; // 0 | 1
  slot_count: number;
  created_at: string;
}

export interface Website {
  id: string;
  user_id: string;
  domain: string;
  api_key_hash: string;
  created_at: string;
}

export interface Session {
  user_id: string;
  is_admin: boolean;
}

export interface Payment {
  id: string;
  user_id: string;
  amount: number;
  slot_increment: number;
  paystack_reference: string;
  created_at: string;
}
