-- Persistent SSO provider links per user
-- Allows "Link Account" from the account portal and stable login across provider account changes.
CREATE TABLE IF NOT EXISTS user_sso_links (
  user_id          TEXT NOT NULL,
  provider         TEXT NOT NULL,
  external_user_id TEXT NOT NULL,
  external_email   TEXT,
  linked_at        INTEGER NOT NULL,
  PRIMARY KEY (user_id, provider)
);

-- Fast lookup by provider + external identity (used during login)
CREATE UNIQUE INDEX IF NOT EXISTS idx_sso_links_provider_uid
  ON user_sso_links (provider, external_user_id);
