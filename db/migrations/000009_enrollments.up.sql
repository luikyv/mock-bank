CREATE TABLE enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    permissions JSONB NOT NULL,
    expires_at TIMESTAMPTZ,
    user_identification TEXT NOT NULL,
    user_rel TEXT NOT NULL,
    owner_id UUID REFERENCES mock_users(id) NOT NULL,
    business_identification TEXT,
    business_rel TEXT,
    account_id UUID REFERENCES accounts(id),
    name TEXT,
    transaction_limit TEXT,
    daily_limit TEXT,
    risk_signals JSONB,
    cancellation JSONB,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    relying_party TEXT NOT NULL,
    challenge TEXT,
    public_key TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

ALTER TABLE payment_consents ADD COLUMN enrollment_id UUID REFERENCES enrollments(id);
ALTER TABLE payment_consents ADD COLUMN enrollment_challenge TEXT;
ALTER TABLE payment_consents ADD COLUMN enrollment_transaction_limit TEXT;
ALTER TABLE payment_consents ADD COLUMN enrollment_daily_limit TEXT;
ALTER TABLE payments ADD COLUMN enrollment_id UUID REFERENCES enrollments(id);

ALTER TABLE recurring_payment_consents ADD COLUMN enrollment_id UUID REFERENCES enrollments(id);
ALTER TABLE recurring_payment_consents ADD COLUMN enrollment_challenge TEXT;
ALTER TABLE recurring_payment_consents ADD COLUMN enrollment_transaction_limit TEXT;
ALTER TABLE recurring_payment_consents ADD COLUMN enrollment_daily_limit TEXT;
ALTER TABLE recurring_payments ADD COLUMN enrollment_id UUID REFERENCES enrollments(id);
