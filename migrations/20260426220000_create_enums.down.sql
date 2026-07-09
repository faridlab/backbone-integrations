-- Down: drop enum types for integrations module
DROP TYPE IF EXISTS integration_status CASCADE;
DROP TYPE IF EXISTS connector_direction CASCADE;
DROP TYPE IF EXISTS connector_kind CASCADE;
