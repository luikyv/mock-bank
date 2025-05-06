CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL,
  organizations JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,

  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE oidc_clients (
    id UUID PRIMARY KEY TEXT,

    org_id TEXT NOT NULL,
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
CREATE INDEX idx_org_id ON mock_users (org_id);
CREATE UNIQUE INDEX unique_orgid_cpf ON mock_users (org_id, cpf);
CREATE UNIQUE INDEX unique_orgid_username ON mock_users (org_id, username);

CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    permissions TEXT[] NOT NULL,
    status_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    user_id UUID REFERENCES mock_users(id),
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id),
    rejected_by TEXT,
    rejection_reason TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_org_id_user_id ON consents (org_id, user_id);
CREATE INDEX idx_org_id_client_id ON consents (org_id, client_id);

CREATE TABLE consent_extensions (
    id                 UUID PRIMARY KEY,
    consent_id         UUID NOT NUL REFERENCES consents(id) ON DELETE CASCADE,
    user_cpf TEXT NOT NULL,
    business_cnpj TEXT,
    expires_at         TIMESTAMPTZ,
    previous_expires_at TIMESTAMPTZ,
    requested_at       TIMESTAMPTZ NOT NULL,
    user_ip_address    TEXT NOT NULL,
    user_agent         TEXT NOT NULL

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
);
CREATE INDEX idx_org_id_consent_id ON consent_extensions (org_id, consent_id);

CREATE TABLE accounts (
    id                           TEXT PRIMARY KEY,
    user_id                      UUID NOT NULL  REFERENCES mock_users(id),
    number                       TEXT NOT NULL,
    type                         TEXT NOT NULL,
    subtype                      TEXT NOT NULL,
    available_amount             TEXT NOT NULL,
    blocked_amount               TEXT NOT NULL,
    automatically_invested_amount TEXT NOT NULL,
    overdraft_limit_contracted   TEXT,
    overdraft_limit_used         TEXT,
    overdraft_limit_unarranged   TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_org_id_user_id ON accounts (org_id, user_id);

CREATE TABLE account_transactions (
    id                           TEXT PRIMARY KEY,
    account_id     UUID NOT NULL REFERENCES accounts(id),
    status         TEXT NOT NULL,
    movement_type  TEXT NOT NULL,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL,
    amount         NUMERIC NOT NULL,
    
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_org_id_account_id ON accounts (org_id, account_id);

CREATE TABLE consent_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id         UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    resource_id         UUID NOT NULL,
    status TEXT NOT NULL,

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX unique_consent_id_resource_id ON consent_resources (consent_id, resource_id);
