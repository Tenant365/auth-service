CREATE TABLE passkey_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  aaguid TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
) STRICT;
CREATE INDEX idx_passkey_user ON passkey_credentials(user_id);
