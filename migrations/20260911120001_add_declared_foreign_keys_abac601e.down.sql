-- Down: drop the declared foreign keys for integrations module
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS fk_integration_events_connector_id;
