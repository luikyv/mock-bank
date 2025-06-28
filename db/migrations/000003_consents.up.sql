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
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
