-- Migration: company row-level-security fence for integrations.integration_accounts
-- (ADR-0008 / ADR-0014 strict company fence). OAuth account connections are
-- company-private: every read and write of an account row is scoped per request
-- via `set_config('app.company_id', <uuid>, true)`; an unset var sees zero rows.
-- The scheduler's claim query binds the same setting on its claim connection, so
-- the fence stays meaningful inside the job.

ALTER TABLE integrations.integration_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.integration_accounts FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integration_accounts_company_isolation ON integrations.integration_accounts;
CREATE POLICY integration_accounts_company_isolation ON integrations.integration_accounts
    FOR ALL
    USING      (company_id = NULLIF(current_setting('app.company_id', true), '')::uuid)
    WITH CHECK (company_id = NULLIF(current_setting('app.company_id', true), '')::uuid);
