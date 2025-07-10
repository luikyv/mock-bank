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
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_mock_users_org_id ON mock_users (org_id);
CREATE UNIQUE INDEX idx_mock_users_org_id_cpf ON mock_users (org_id, cpf);
CREATE UNIQUE INDEX idx_mock_users_org_id_cnpj ON mock_users (org_id, cnpj);
CREATE UNIQUE INDEX idx_mock_users_org_id_username ON mock_users (org_id, username);

-- mock_user_business associates individual users with business users (i.e., users that own a CNPJ).
CREATE TABLE mock_user_business (
    user_id UUID NOT NULL REFERENCES mock_users(id) ON DELETE CASCADE,
    business_user_id UUID NOT NULL REFERENCES mock_users(id) ON DELETE CASCADE,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,

    PRIMARY KEY (user_id, business_user_id)
);
CREATE INDEX idx_mock_user_business_org_id ON mock_user_business (org_id);

CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    name TEXT,
    webhook_uris JSONB,
    origin_uris JSONB,

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
CREATE INDEX idx_oauth_sessions_org_id ON oauth_sessions (org_id);
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
CREATE INDEX idx_oauth_grants_org_id ON oauth_grants (org_id);
CREATE INDEX idx_oauth_grants_token_id ON oauth_grants (token_id);
CREATE INDEX idx_oauth_grants_refresh_token_id ON oauth_grants (refresh_token_id);
CREATE INDEX idx_oauth_grants_auth_code ON oauth_grants (auth_code);

CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    permissions JSONB NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ,
    owner_id UUID REFERENCES mock_users(id) NOT NULL,
    user_identification TEXT NOT NULL,
	user_rel TEXT NOT NULL,
    business_identification TEXT,
	business_rel TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    rejection JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_consents_org_id ON consents (org_id);

CREATE TABLE consent_extensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    user_identification TEXT NOT NULL,
	user_rel TEXT NOT NULL,
    business_identification TEXT,
	business_rel TEXT,
    expires_at TIMESTAMPTZ,
    previous_expires_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ NOT NULL,
    user_ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_consent_extensions_org_id ON consent_extensions (org_id);

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES mock_users(id),
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
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_accounts_org_id ON accounts (org_id);
CREATE UNIQUE INDEX idx_accounts_org_id_number ON accounts (org_id, number);

CREATE TABLE consent_accounts (
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES mock_users(id),
    status TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,

    PRIMARY KEY (consent_id, account_id)
);
CREATE INDEX idx_consent_accounts_org_id ON consent_accounts (org_id);

CREATE TABLE account_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    date_time TIMESTAMPTZ NOT NULL,
    movement_type TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    amount TEXT NOT NULL,
    partie_branch_code TEXT,
    partie_check_digit TEXT,
    partie_cnpj_cpf TEXT,
    partie_compe_code TEXT,
    partie_number TEXT,
    partie_person_type TEXT,

    org_id TEXT NOT NULL,
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_account_transactions_org_id ON account_transactions (org_id);

CREATE TABLE credit_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES mock_users(id),
    number TEXT NOT NULL,
    ipoc_code TEXT NOT NULL,
    product_name TEXT NOT NULL,
    product_type TEXT NOT NULL,
    date DATE NOT NULL,
    disbursement_dates JSONB,
    settlement_date DATE,
    amount TEXT NOT NULL,
    currency TEXT,
    due_date DATE,
    instalment_periodicity TEXT NOT NULL,
    instalment_periodicity_additional_info TEXT,
    first_instalment_due_date DATE,
    cet TEXT NOT NULL,
    amortization_schedule TEXT NOT NULL,
    amortization_schedule_additional_info TEXT,
    interest_rates JSONB,
    contracted_fees JSONB,
    finance_charges JSONB,
    product_subtype TEXT NOT NULL,
    product_subtype_category TEXT NOT NULL,
    cnpj_consignee TEXT,
    next_instalment_amount TEXT,
    outstanding_balance TEXT NOT NULL,
    paid_instalments INT,
    due_instalments INT NOT NULL,
    past_due_instalments INT NOT NULL,
    total_instalments INT,
    total_instalment_type TEXT,
    remaining_instalments INT,
    remaining_instalment_type TEXT,

    org_id TEXT NOT NULL,
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_credit_contracts_org_id ON credit_contracts (org_id);

CREATE TABLE consent_credit_contracts (
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES credit_contracts(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES mock_users(id),
    status TEXT NOT NULL,
    type TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,

    PRIMARY KEY (consent_id, contract_id)
);
CREATE INDEX idx_consent_credit_contracts_org_id ON consent_credit_contracts (org_id);

CREATE TABLE credit_contract_warranties (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES credit_contracts(id) ON DELETE CASCADE,
    currency TEXT NOT NULL,
    amount TEXT NOT NULL,
    type TEXT NOT NULL,
    subtype TEXT NOT NULL,

    org_id TEXT NOT NULL,
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_credit_contract_warranties_org_id ON credit_contract_warranties (org_id);

CREATE TABLE credit_contract_release_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES credit_contracts(id) ON DELETE CASCADE,
    is_over_parcel_payment BOOLEAN NOT NULL,
    instalment_id TEXT,
    date DATE NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    over_parcel JSONB,

    org_id TEXT NOT NULL,
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_credit_contract_release_payments_org_id ON credit_contract_release_payments (org_id);

CREATE TABLE credit_contract_balloon_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES credit_contracts(id) ON DELETE CASCADE,
    due_date DATE NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,

    org_id TEXT NOT NULL,
    cross_org BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_credit_contract_balloon_payments_org_id ON credit_contract_balloon_payments (org_id);

CREATE OR REPLACE VIEW consent_resources AS
    WITH authorised_consents AS (SELECT id, org_id FROM consents WHERE status = 'AUTHORISED')

    SELECT
        'ACCOUNT' AS resource_type,
        consent_accounts.consent_id,
        consent_accounts.account_id AS resource_id,
        consent_accounts.owner_id,
        consent_accounts.status,
        consent_accounts.org_id,
        consent_accounts.created_at,
        consent_accounts.updated_at
    FROM consent_accounts
    JOIN authorised_consents ON consent_accounts.consent_id = authorised_consents.id AND consent_accounts.org_id = authorised_consents.org_id

    UNION ALL

    SELECT
        consent_credit_contracts.type AS resource_type,
        consent_credit_contracts.consent_id,
        consent_credit_contracts.contract_id AS resource_id,
        consent_credit_contracts.owner_id,
        consent_credit_contracts.status,
        consent_credit_contracts.org_id,
        consent_credit_contracts.created_at,
        consent_credit_contracts.updated_at
    FROM consent_credit_contracts
    JOIN authorised_consents ON consent_credit_contracts.consent_id = authorised_consents.id AND consent_credit_contracts.org_id = authorised_consents.org_id;

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
CREATE INDEX idx_enrollments_org_id ON enrollments (org_id);

CREATE TABLE payment_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    owner_id UUID REFERENCES mock_users(id) NOT NULL,
    user_identification TEXT NOT NULL,
	user_rel            TEXT NOT NULL,
	business_identification TEXT,
	business_rel TEXT,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    creditor_type TEXT NOT NULL,
    creditor_cpf_cnpj TEXT NOT NULL,
    creditor_name TEXT NOT NULL,
    creditor_account_isbp TEXT NOT NULL,
    creditor_account_issuer TEXT,
    creditor_account_number TEXT NOT NULL,
    creditor_account_type TEXT NOT NULL,
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
    enrollment_id UUID REFERENCES enrollments(id),
    enrollment_challenge TEXT,
    enrollment_transaction_limit TEXT,
    enrollment_daily_limit TEXT,
    rejection JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payment_consents_org_id ON payment_consents (org_id);

CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    end_to_end_id TEXT NOT NULL,
    local_instrument TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    creditor_account_isbp TEXT NOT NULL,
    creditor_account_issuer TEXT,
    creditor_account_number TEXT NOT NULL,
    creditor_account_type TEXT NOT NULL,
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
    enrollment_id UUID REFERENCES enrollments(id),
    date DATE,
    rejection JSONB,
    cancellation JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payments_org_id ON payments (org_id);

CREATE TABLE recurring_payment_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ NOT NULL,
    authorized_at TIMESTAMPTZ,
    approval_due_at DATE,
    expires_at TIMESTAMPTZ,
    owner_id UUID REFERENCES mock_users(id) NOT NULL,
    user_identification TEXT NOT NULL,
	user_rel            TEXT NOT NULL,
	business_identification TEXT,
	business_rel TEXT,
    creditors JSONB NOT NULL,
    additional_info TEXT,
    configuration JSONB NOT NULL,
    risk_signals JSONB,
    account_id UUID REFERENCES accounts(id),
    rejection JSONB,
    revocation JSONB,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    enrollment_id UUID REFERENCES enrollments(id),
    enrollment_challenge TEXT,
    enrollment_transaction_limit TEXT,
    enrollment_daily_limit TEXT,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recurring_payment_consents_org_id ON recurring_payment_consents (org_id);

CREATE TABLE recurring_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id UUID NOT NULL REFERENCES recurring_payment_consents(id),
    end_to_end_id TEXT NOT NULL,
    date DATE NOT NULL,
    status TEXT NOT NULL,
    status_updated_at TIMESTAMPTZ NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    creditor_account_isbp TEXT NOT NULL,
    creditor_account_issuer TEXT,
    creditor_account_number TEXT NOT NULL,
    creditor_account_type TEXT NOT NULL,
    remittance_information TEXT,
    cnpj_initiator TEXT NOT NULL,
    ibge_town_code TEXT,
    authorisation_flow TEXT,
    local_instrument TEXT NOT NULL,
    proxy TEXT,
    transaction_identification TEXT,
    document_identification TEXT NOT NULL,
    document_rel TEXT NOT NULL,
    original_id UUID REFERENCES recurring_payments(id),
    reference TEXT,
    risk_signals JSONB,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    account_id UUID REFERENCES accounts(id),
    enrollment_id UUID REFERENCES enrollments(id),
    rejection JSONB,
    cancellation JSONB,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_recurring_payments_org_id ON recurring_payments (org_id);

CREATE TABLE idempotency_records (
    id TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL,
    request TEXT NOT NULL,
    response TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_idempotency_records_org_id ON idempotency_records (org_id);

CREATE TABLE jwt_ids (
    id TEXT PRIMARY KEY,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_jwt_ids_org_id ON jwt_ids (org_id);

CREATE TABLE schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_type TEXT NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX idx_schedules_org_id ON schedules (org_id);
