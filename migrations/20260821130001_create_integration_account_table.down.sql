-- Down: drop integrations.integration_accounts table
DROP TABLE IF EXISTS integrations.integration_accounts CASCADE;
DROP FUNCTION IF EXISTS integrations.integration_accounts_audit_timestamp() CASCADE;
DROP TYPE IF EXISTS o_auth_provider;
DROP TYPE IF EXISTS integration_account_status;
