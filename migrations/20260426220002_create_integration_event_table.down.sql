-- Down: drop integrations.integration_events table
DROP TABLE IF EXISTS integrations.integration_events CASCADE;
DROP FUNCTION IF EXISTS integrations.integration_events_audit_timestamp() CASCADE;
