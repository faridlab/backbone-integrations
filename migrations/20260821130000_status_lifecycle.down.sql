-- Down: restore the is_active boolean exactly as it was.
-- Only 'inactive' rows are written back as FALSE; rows at the column default
-- map to the boolean default TRUE without an UPDATE.

ALTER TABLE integrations.integration_connectors ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
UPDATE integrations.integration_connectors SET is_active = FALSE WHERE status = 'inactive';
ALTER TABLE integrations.integration_connectors DROP COLUMN status;

DROP TYPE IF EXISTS connector_status;
