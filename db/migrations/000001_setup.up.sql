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

CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    data JSONB NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_oauth_clients_org_id ON oauth_clients (org_id);

CREATE TABLE oauth_sessions (
    id TEXT PRIMARY KEY,
    callback_id TEXT,
    auth_code TEXT,
    pushed_auth_req_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_oauth_sessions_callback_id ON oauth_sessions (callback_id);
CREATE INDEX idx_oauth_sessions_auth_code ON oauth_sessions (auth_code);
CREATE INDEX idx_oauth_sessions_pushed_auth_req_id ON oauth_sessions (pushed_auth_req_id);

CREATE TABLE oauth_grants (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    refresh_token_id TEXT,
    auth_code TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    data JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_oauth_grants_token_id ON oauth_grants (token_id);
CREATE INDEX idx_oauth_grants_refresh_token_id ON oauth_grants (refresh_token_id);
CREATE INDEX idx_oauth_grants_auth_code ON oauth_grants (auth_code);

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

CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    permissions JSONB NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ,
    user_id UUID REFERENCES mock_users(id),
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    rejection JSONB,

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
    user_id UUID NOT NULL REFERENCES mock_users(id),
    status TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),

    PRIMARY KEY (consent_id, account_id)
);
CREATE INDEX idx_consent_accounts_org_id_user_id ON consent_accounts (org_id, user_id);

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
    ca.consent_id,
    ca.account_id AS resource_id,
    ca.user_id,
    ca.status,
    ca.org_id,
    ca.created_at,
    ca.updated_at
FROM consent_accounts ca
JOIN consents c ON ca.consent_id = c.id
WHERE c.status = 'AUTHORISED';

CREATE TABLE payment_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    user_id UUID REFERENCES mock_users(id),
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    creditor JSONB NOT NULL,
    creditor_account JSONB NOT NULL,
    payment_type TEXT NOT NULL,
    payment_schedule JSONB,
    payment_date DATE,
    payment_currency TEXT NOT NULL,
    payment_amount TEXT NOT NULL,
    ibge_town_code TEXT,
    local_instrument TEXT NOT NULL,
    qr_code TEXT,
    proxy TEXT,
    account_id UUID REFERENCES accounts(id),
    rejection JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payment_consents_org_id_account_id ON payment_consents (org_id, account_id);

CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    end_to_end_id TEXT NOT NULL UNIQUE,
    local_instrument TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    creditor_account JSONB NOT NULL,
    remittance_information TEXT,
    qr_code TEXT,
    proxy TEXT,
    cnpj_initiator TEXT NOT NULL,
    transaction_identification TEXT,
    ibge_town_code TEXT,
    authorisation_flow TEXT,
    consent_id UUID NOT NULL REFERENCES payment_consents(id),
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    date DATE,
    rejection JSONB,
    cancellation JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payments_org_id_consent_id ON payments (org_id, consent_id);

CREATE TABLE idempotency_records (
    id TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL,
    request TEXT NOT NULL,
    response TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
