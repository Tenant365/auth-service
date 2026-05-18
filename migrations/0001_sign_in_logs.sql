CREATE TABLE IF NOT EXISTS sign_in_logs (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ip_address TEXT,
  country TEXT,
  city TEXT,
  user_agent TEXT,
  provider TEXT NOT NULL DEFAULT 'password'
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sign_in_logs_user_id ON sign_in_logs(user_id, created_at DESC);
