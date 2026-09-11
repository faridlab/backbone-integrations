-- Hand-authored (user-owned). Not regenerated.
--
-- Best-effort restore sketch for the tenancy strip (ADR-0029). This is a breaking module
-- release against dev-stage databases: the down re-adds the company_id column as nullable
-- with the company-leading indexes in their exact pre-strip shapes, but restores NO data —
-- rows written after the strip (or after the decorator re-keyed them) carry org_unit_id
-- only. The composing service's tenancy decorator remains the live fence; the
-- <table>_company_isolation policies are NOT recreated here. Treat this down as a
-- schema-shape sketch for archaeology, not a usable rollback.

ALTER TABLE integrations.integration_connectors ADD COLUMN IF NOT EXISTS company_id uuid;
ALTER TABLE integrations.integration_events      ADD COLUMN IF NOT EXISTS company_id uuid;
ALTER TABLE integrations.integration_accounts    ADD COLUMN IF NOT EXISTS company_id uuid;

-- ── integration_connectors ─────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_integration_connectors_company_id_provider
    ON integrations.integration_connectors (company_id, provider);

-- ── integration_events ─────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_integration_events_company_id_status
    ON integrations.integration_events (company_id, status);

-- ── integration_accounts ───────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_integration_accounts_company_id_provider_account_ref
    ON integrations.integration_accounts (company_id, provider, account_ref);
CREATE INDEX IF NOT EXISTS idx_integration_accounts_company_id_status
    ON integrations.integration_accounts (company_id, status);
