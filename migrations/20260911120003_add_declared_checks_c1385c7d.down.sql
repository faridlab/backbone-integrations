-- Down: drop the declared rule constraints for integrations module
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_error_detail_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_mapped_ref_type_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_payload_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_payload_required__required;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_business_key_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_business_key_required__required;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_external_id_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_external_id_required__required;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_event_type_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_event_type_required__required;
ALTER TABLE IF EXISTS integrations.integration_events DROP CONSTRAINT IF EXISTS ck_integration_events_connector_id_required__required;
DO $$
BEGIN
    IF to_regclass('integrations.uq_integration_events_business_key__unique') IS NOT NULL AND to_regclass('integrations.idx_integration_events_connector_id_business_key') IS NULL THEN
        ALTER INDEX integrations.uq_integration_events_business_key__unique RENAME TO idx_integration_events_connector_id_business_key;
    END IF;
END $$;

ALTER TABLE IF EXISTS integrations.integration_accounts DROP CONSTRAINT IF EXISTS ck_integration_accounts_pkce_verifier_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_accounts DROP CONSTRAINT IF EXISTS ck_integration_accounts_account_ref_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_accounts DROP CONSTRAINT IF EXISTS ck_integration_accounts_account_ref_required__required;
ALTER TABLE IF EXISTS integrations.integration_connectors DROP CONSTRAINT IF EXISTS ck_integration_connectors_provider_max_length__max_length;
ALTER TABLE IF EXISTS integrations.integration_connectors DROP CONSTRAINT IF EXISTS ck_integration_connectors_provider_required__required;
