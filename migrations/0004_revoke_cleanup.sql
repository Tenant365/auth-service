-- Track auth-service session JTI so it can be invalidated on revoke
ALTER TABLE sign_in_logs ADD COLUMN auth_jti TEXT;
-- Track when a sign-in session was revoked
ALTER TABLE sign_in_logs ADD COLUMN revoked_at INTEGER;

CREATE INDEX idx_sign_in_logs_auth_jti ON sign_in_logs(auth_jti);
