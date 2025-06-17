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
