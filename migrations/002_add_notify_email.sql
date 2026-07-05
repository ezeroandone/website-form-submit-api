-- Add notification email and verification fields to websites table
ALTER TABLE websites ADD COLUMN notify_email TEXT NOT NULL DEFAULT '';
ALTER TABLE websites ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE websites ADD COLUMN verify_token TEXT;
