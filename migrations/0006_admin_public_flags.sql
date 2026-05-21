-- Admin flag on users: allows marking individual users as platform admins.
ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0;

-- Public flag on oauth2_applications: bypasses tenant restriction so any
-- tenant's users can authenticate against the app.
ALTER TABLE oauth2_applications ADD COLUMN public INTEGER NOT NULL DEFAULT 0;
