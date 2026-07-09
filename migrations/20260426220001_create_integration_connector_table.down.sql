-- Down: drop integrations.integration_connectors table
DROP TABLE IF EXISTS integrations.integration_connectors CASCADE;
DROP FUNCTION IF EXISTS integrations.integration_connectors_audit_timestamp() CASCADE;
