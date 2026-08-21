-- Migration: replace the integration-connector lifecycle boolean with a status enum
-- integrations.integration_connectors carried `is_active BOOLEAN NOT NULL DEFAULT TRUE`; the
-- tree-wide convention is one `status` enum field per lifecycle (see docs/refactoring-schema in
-- the serpa workspace). The boolean migrates only rows deviating from its own column default.
-- The enum type is created unqualified so it lands beside the module's other enum types (public),
-- where the generated sqlx type_name resolves.

DO $$ BEGIN
    CREATE TYPE connector_status AS ENUM ('active', 'inactive');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE integrations.integration_connectors ADD COLUMN status connector_status NOT NULL DEFAULT 'active';
UPDATE integrations.integration_connectors SET status = 'inactive' WHERE NOT is_active;
ALTER TABLE integrations.integration_connectors DROP COLUMN is_active;
