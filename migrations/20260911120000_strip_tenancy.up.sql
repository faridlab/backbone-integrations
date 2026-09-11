-- Hand-authored (user-owned). Not regenerated.
--
-- Strip every company-fence artifact from the integration tables (ADR-0029): the module is
-- tenant-agnostic; org scoping is installed by the COMPOSING service's tenancy decorator,
-- never by the module. Dropped here, per table: the company-leading indexes, the
-- <table>_company_isolation RLS policy, and the company_id column itself.
--
-- Ordering guard (the decorator must run FIRST on any database with data): the module
-- never moves tenancy data. A table is safe to strip when EITHER
--   a) it carries org_unit_id with no NULLs — the decorator backfilled it from company_id —
--      or b) it is empty (a fresh database: the earlier chain files created it empty).
-- Otherwise the strip RAISEs, naming the decorator step, rather than dropping a column
-- that still holds the only tenancy key. The file is re-runnable (every drop is IF EXISTS
-- and the tracker has no checksums), so a failed run retries cleanly after the decorator
-- lands.
--
-- The module's outbox table (integrations.outbox_events) is deliberately NOT touched: its
-- tenant column survives the strip because the cross-tenant relay that drains the outbox
-- still keys on it.
--
-- RLS enable/force flags are deliberately NOT touched: the decorator owns those now.

DO $$
DECLARE
    t text;
    has_org boolean;
    org_nulls bigint;
    total bigint;
    offenders text := '';
BEGIN
    FOREACH t IN ARRAY ARRAY['integration_connectors', 'integration_events', 'integration_accounts']
    LOOP
        IF to_regclass(format('integrations.%I', t)) IS NULL THEN
            CONTINUE; -- chain not fully applied on this database; nothing to strip
        END IF;

        SELECT EXISTS (
                   SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'integrations' AND table_name = t AND column_name = 'org_unit_id'
               )
        INTO has_org;

        EXECUTE format('SELECT count(*) FROM integrations.%I', t) INTO total;

        IF has_org THEN
            EXECUTE format(
                'SELECT count(*) FROM integrations.%I WHERE org_unit_id IS NULL', t)
            INTO org_nulls;
        ELSE
            org_nulls := total; -- no org column: every row's only tenancy key is company_id
        END IF;

        IF has_org AND org_nulls = 0 THEN
            CONTINUE; -- decorator backfilled: safe
        END IF;
        IF total = 0 THEN
            CONTINUE; -- empty table (fresh database): safe
        END IF;
        offenders := offenders || format(' integrations.%s (%s rows, %s rows not covered by org_unit_id);', t, total, org_nulls);
    END LOOP;

    IF offenders <> '' THEN
        RAISE EXCEPTION 'refusing to strip company_id — these tables are not yet covered by the tenancy decorator:%. Apply the composing service''s tenancy decorator (it backfills org_unit_id from company_id) and re-run; it is the only step that moves tenancy data.', offenders;
    END IF;
END $$;

-- ── integration_connectors ─────────────────────────────────────────────────────
DO $$
BEGIN
    -- Per-table guard (mirrors the ordering block above): a database that has not
    -- applied this table's chain files — the oauth probe harness applies only the
    -- account-table subset — must still accept this file verbatim.
    IF to_regclass('integrations.integration_connectors') IS NULL THEN RETURN; END IF;
    DROP INDEX IF EXISTS integrations.idx_integration_connectors_company_id_provider;
    DROP POLICY IF EXISTS integration_connectors_company_isolation ON integrations.integration_connectors;
    ALTER TABLE integrations.integration_connectors DROP COLUMN IF EXISTS company_id;
END $$;

-- ── integration_events ─────────────────────────────────────────────────────────
DO $$
BEGIN
    -- Per-table guard (mirrors the ordering block above): a database that has not
    -- applied this table's chain files — the oauth probe harness applies only the
    -- account-table subset — must still accept this file verbatim.
    IF to_regclass('integrations.integration_events') IS NULL THEN RETURN; END IF;
    DROP INDEX IF EXISTS integrations.idx_integration_events_company_id_status;
    DROP POLICY IF EXISTS integration_events_company_isolation ON integrations.integration_events;
    ALTER TABLE integrations.integration_events DROP COLUMN IF EXISTS company_id;
END $$;

-- ── integration_accounts ───────────────────────────────────────────────────────
DO $$
BEGIN
    -- Per-table guard (mirrors the ordering block above): a database that has not
    -- applied this table's chain files — the oauth probe harness applies only the
    -- account-table subset — must still accept this file verbatim.
    IF to_regclass('integrations.integration_accounts') IS NULL THEN RETURN; END IF;
    DROP INDEX IF EXISTS integrations.idx_integration_accounts_company_id_provider_account_ref;
    DROP INDEX IF EXISTS integrations.idx_integration_accounts_company_id_status;
    DROP POLICY IF EXISTS integration_accounts_company_isolation ON integrations.integration_accounts;
    ALTER TABLE integrations.integration_accounts DROP COLUMN IF EXISTS company_id;
END $$;

-- Uniques that survive are already tenant-free and are NOT restored or re-created here:
--   • integrations.idx_integration_events_connector_id_business_key (the webhook dedup)
--     carries no company column and keeps its exact pre-strip shape.
--   • The per-unit "one connector per provider" unique is POSTURE — the composing
--     service's tenancy decorator re-declares it org_unit_id-leading; the pre-strip
--     company-leading form is intentionally gone.
