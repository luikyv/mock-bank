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
