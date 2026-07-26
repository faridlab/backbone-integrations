-- ADR-0011: bring this module's outbox_events to parity with backbone_outbox::outbox::migrate.
-- The local outbox migration (20260709/12...) predates the company_id column + tenant fence the
-- canonical migrate creates, so outbox::stage — which inserts company_id — failed at runtime
-- ("column ... company_id ... does not exist"). Add the column + index + the same RLS fence.
-- The cross-tenant relay logs in as 'metaphor_relay' to drain (per the canonical policy).

ALTER TABLE integrations.outbox_events
    ADD COLUMN IF NOT EXISTS company_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

CREATE INDEX IF NOT EXISTS idx_integrations_outbox_company_id ON integrations.outbox_events (company_id);

ALTER TABLE integrations.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.outbox_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_events_company_isolation ON integrations.outbox_events;
CREATE POLICY outbox_events_company_isolation ON integrations.outbox_events
    FOR ALL
    USING      (company_id = NULLIF(current_setting('app.company_id', true), '')::uuid
                OR current_user = 'metaphor_relay')
    WITH CHECK (company_id = NULLIF(current_setting('app.company_id', true), '')::uuid
                OR current_user = 'metaphor_relay');
