DROP TABLE IF EXISTS verifications;

CREATE TABLE verifications (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(255) NOT NULL,
  	user UUID NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  	FOREIGN KEY (user) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_verifications_email ON verifications (email);

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS tenants;

-- tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL
);

CREATE INDEX idx_tenants_name ON tenants (name);

-- organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    tenant UUID NOT NULL, -- tenants
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (tenant) REFERENCES tenants (id)
);

CREATE INDEX idx_organizations_name ON organizations (name);

-- users
CREATE TABLE users (
    id UUID PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    tenant UUID,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (tenant) REFERENCES tenants (id)
);

CREATE INDEX idx_users_email ON users (email);

CREATE TABLE register_verifications (
    id UUID PRIMARY KEY,
    "user" UUID NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY ("user") REFERENCES users (id)
);

CREATE INDEX idx_register_verifications_user_expires_at ON register_verifications ("user", expires_at);