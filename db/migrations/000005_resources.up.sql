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
