-- Down: remove the company RLS fence from integrations.integration_accounts
DROP POLICY IF EXISTS integration_accounts_company_isolation ON integrations.integration_accounts;
ALTER TABLE integrations.integration_accounts NO FORCE  ROW LEVEL SECURITY;
ALTER TABLE integrations.integration_accounts DISABLE ROW LEVEL SECURITY;
