PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  google_id   TEXT UNIQUE NOT NULL,
  email       TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  is_admin    INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
  slot_count  INTEGER NOT NULL DEFAULT 1 CHECK (slot_count >= 1),
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS websites (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  domain       TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE (user_id, domain)
);

CREATE TABLE IF NOT EXISTS payments (
  id                 TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  amount             INTEGER NOT NULL CHECK (amount >= 1),
  slot_increment     INTEGER NOT NULL CHECK (slot_increment >= 1),
  paystack_reference TEXT UNIQUE NOT NULL,
  created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id);
CREATE INDEX IF NOT EXISTS idx_websites_api_key_hash ON websites(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
