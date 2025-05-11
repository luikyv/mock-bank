DROP INDEX IF EXISTS unique_consent_id_resource_id;
DROP TABLE IF EXISTS consent_resources;

DROP INDEX IF EXISTS idx_org_id_account_id;
DROP TABLE IF EXISTS account_transactions;

DROP INDEX IF EXISTS idx_org_id_numer;
DROP INDEX IF EXISTS idx_org_id_user_id;
DROP TABLE IF EXISTS accounts;

DROP INDEX IF EXISTS idx_org_id_consent_id;
DROP TABLE IF EXISTS consent_extensions;

DROP INDEX IF EXISTS idx_org_id_client_id;
DROP INDEX IF EXISTS idx_org_id_user_id;
DROP TABLE IF EXISTS consents;

DROP INDEX IF EXISTS unique_orgid_username;
DROP INDEX IF EXISTS unique_orgid_cpf;
DROP INDEX IF EXISTS idx_org_id;
DROP TABLE IF EXISTS mock_users;

DROP TABLE IF EXISTS sessions;

DROP EXTENSION IF EXISTS "pgcrypto" CASCADE;
