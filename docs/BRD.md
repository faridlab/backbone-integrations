# backbone-integrations — BRD

## Documents
IntegrationConnector (a provider connection) · IntegrationEvent (one inbound event + its outcome). Own
Postgres schema `integrations`. Posts **no GL**. Reaches modules only through their public write path.

## Business rules

**BR-1 (connector).** `register_connector` records a connection to a provider — unique per (company,
provider) — with its kind + direction. Only an **active** connector processes events.

**BR-2 (idempotent receive — the invariant).** `receive_event` records an inbound event and maps it to an
internal action. Deduped on the **business key** (the order/transaction ref + terminal state the caller
supplies), NOT the raw notification id — because a gateway sends multiple settled-class notifications for
one order with different notification ids, and keying on the notification id would apply the payment twice
(maturity council 2026-07-11). A retry (same business key) returns the original (`duplicate=true`) and never
re-maps.

**BR-3 (map / ignore / fail).** The event maps via the `TargetPort` to the target module's write path — a
settled payment → `backbone-payment`, a marketplace order → `backbone-selling`. Outcomes: `mapped` (an
internal record created, ref recorded) + `IntegrationEventMapped`; `ignored` (no internal action needed,
e.g. a "pending" notification) + `IntegrationEventIgnored`; `failed` (recorded reason) +
`IntegrationEventFailed`. The `idempotency_key` forwarded to the target is the business key, so the target
also dedups. The lifecycle event is staged in the same tx as the status update (durable).

## Events
`IntegrationEventMapped` (event_id, company/connector, event_type, external_id, internal_ref_type/id),
`IntegrationEventFailed` (event_id, reason), `IntegrationEventIgnored` (event_id, reason).

## Deferred (with reason)
Concrete provider adapters (webhook verify/parse), outbound push, credential storage (tier5-deferred §7).
