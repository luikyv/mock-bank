CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    permissions JSONB NOT NULL,
    status_updated_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ,
    user_id UUID REFERENCES mock_users(id),
    user_identification TEXT NOT NULL,
	user_rel TEXT NOT NULL,
	business_dentification TEXT,
	business_rel TEXT,
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
