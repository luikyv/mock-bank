CREATE TABLE idempotency_records (
    id TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL,
    request TEXT NOT NULL,
    response TEXT NOT NULL,

    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
