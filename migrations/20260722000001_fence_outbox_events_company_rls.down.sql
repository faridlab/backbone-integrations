DROP POLICY IF EXISTS outbox_events_company_isolation ON integrations.outbox_events;
ALTER TABLE integrations.outbox_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.outbox_events DISABLE ROW LEVEL SECURITY;
DROP INDEX IF EXISTS integrations.idx_integrations_outbox_company_id;
ALTER TABLE integrations.outbox_events DROP COLUMN IF EXISTS company_id;
