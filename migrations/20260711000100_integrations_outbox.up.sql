CREATE TABLE IF NOT EXISTS integrations.outbox_events (
  id uuid PRIMARY KEY, event_type text NOT NULL, aggregate_type text NOT NULL, aggregate_id text NOT NULL,
  payload jsonb NOT NULL, occurred_at timestamptz NOT NULL, correlation_id text, causation_id text,
  version int NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz );
CREATE INDEX IF NOT EXISTS idx_integrations_outbox_unpublished ON integrations.outbox_events (occurred_at) WHERE published_at IS NULL;
CREATE TABLE IF NOT EXISTS integrations.inbox_consumed (
  consumer text NOT NULL, event_id uuid NOT NULL, consumed_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (consumer, event_id) );
