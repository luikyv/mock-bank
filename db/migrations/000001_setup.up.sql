-- Enable cryptographic functions for UUID generation.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    organizations JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE mock_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    cpf TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_mock_users_org_id ON mock_users (org_id);
CREATE UNIQUE INDEX idx_mock_users_org_id_cpf ON mock_users (org_id, cpf);
CREATE UNIQUE INDEX idx_mock_users_org_id_username ON mock_users (org_id, username);

CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    permissions TEXT[] NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ,
    user_id UUID REFERENCES mock_users(id),
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    client_id TEXT NOT NULL,
    rejected_by TEXT,
    rejection_reason TEXT,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_consents_org_id_user_id ON consents (org_id, user_id);
CREATE INDEX idx_consents_org_id_client_id ON consents (org_id, client_id);

CREATE TABLE consent_extensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    expires_at TIMESTAMPTZ,
    previous_expires_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ NOT NULL,
    user_ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_consent_extensions_org_id_consent_id ON consent_extensions (org_id, consent_id);

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES mock_users(id),
    number TEXT NOT NULL,
    type TEXT NOT NULL,
    subtype TEXT NOT NULL,
    available_amount TEXT NOT NULL,
    blocked_amount TEXT NOT NULL,
    automatically_invested_amount TEXT NOT NULL,
    overdraft_limit_contracted TEXT,
    overdraft_limit_used TEXT,
    overdraft_limit_unarranged TEXT,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_accounts_org_id_user_id ON accounts (org_id, user_id);
CREATE UNIQUE INDEX idx_accounts_org_id_number ON accounts (org_id, number);

CREATE TABLE consent_accounts (
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (consent_id, account_id)
);

CREATE TABLE account_transactions (
    id TEXT PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    status TEXT NOT NULL,
    movement_type TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    amount TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_account_transactions_org_id_account_id ON account_transactions (org_id, account_id);

CREATE OR REPLACE VIEW consent_resources AS
SELECT
    'ACCOUNT' AS resource_type,
    consent_id,
    account_id AS resource_id,
    status,
    org_id,
    created_at,
    updated_at
FROM consent_accounts;