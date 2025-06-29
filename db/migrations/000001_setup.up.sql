-- Enable cryptographic functions for UUID generation.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    organizations JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    code_verifier TEXT,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE mock_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    cpf TEXT NOT NULL,
    cnpj TEXT,
    description TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_mock_users_org_id ON mock_users (org_id);
CREATE UNIQUE INDEX idx_mock_users_org_id_cpf ON mock_users (org_id, cpf);
CREATE UNIQUE INDEX idx_mock_users_org_id_cnpj ON mock_users (org_id, cnpj);
CREATE UNIQUE INDEX idx_mock_users_org_id_username ON mock_users (org_id, username);

CREATE TABLE mock_user_business (
    user_id UUID NOT NULL REFERENCES mock_users(id) ON DELETE CASCADE,
    business_user_id UUID NOT NULL REFERENCES mock_users(id) ON DELETE CASCADE,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,

    PRIMARY KEY (user_id, business_user_id)
);
CREATE INDEX idx_mock_user_business_org_id ON mock_user_business (org_id);
