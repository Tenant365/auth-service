ALTER TABLE sign_in_logs ADD COLUMN oauth2_jti TEXT;
CREATE INDEX idx_sign_in_logs_oauth2_jti ON sign_in_logs(oauth2_jti);
