-- Enable cryptographic functions for UUID generation.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    organizations JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    code_verifier TEXT,

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE mock_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    cpf TEXT NOT NULL,
    description TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_mock_users_org_id ON mock_users (org_id);
CREATE UNIQUE INDEX idx_mock_users_org_id_cpf ON mock_users (org_id, cpf);
CREATE UNIQUE INDEX idx_mock_users_org_id_username ON mock_users (org_id, username);
