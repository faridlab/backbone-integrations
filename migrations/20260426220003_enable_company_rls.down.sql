-- Down: remove the company RLS fence for integrations module

-- Reverse the company RLS fence for integrations.integration_connectors
DROP POLICY IF EXISTS integration_connectors_company_isolation ON integrations.integration_connectors;
ALTER TABLE integrations.integration_connectors NO FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.integration_connectors DISABLE ROW LEVEL SECURITY;

-- Reverse the company RLS fence for integrations.integration_events
DROP POLICY IF EXISTS integration_events_company_isolation ON integrations.integration_events;
ALTER TABLE integrations.integration_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.integration_events DISABLE ROW LEVEL SECURITY;

