# backbone-integrations — Extension Guide

## Public surface (stable)
- **Target port** (`application::service::integrations_ports`): `TargetPort` + DTOs (`MapRequest`,
  `MapOutcome` = `Mapped(MappedRef)` | `Ignored(reason)`, `MapRejected`) — the seam each event drives,
  implemented over the target module's WRITE PATH. `MapRequest.idempotency_key` (the event id) MUST be
  honored as the target's idempotency key.
- **Events** (`application::service::integrations_events`): `IntegrationEventMapped`,
  `IntegrationEventFailed`, `IntegrationEventIgnored`, the `IntegrationEvent` union, `IntegrationEventSink`.
- **Write path** (`application::service::integrations_write_service::IntegrationsWriteService`):
  `register_connector`, `receive_event`, with `NewConnector`/`InboundEvent`/`ReceiveOutcome`.
- **Durability**: the lifecycle event is staged in `integrations.outbox_events` in the same tx as the
  status update.

## How a consuming service uses integrations
Verify + parse the provider webhook (Midtrans HMAC, Tokopedia OAuth) into a structured `payload` and call
`receive_event(InboundEvent { connector_id, event_type, external_id, raw, payload }, mapper, sink)`.
Implement `TargetPort::map` over the target module — a settled payment → payment `create_payment` (proven),
a marketplace order → selling — returning `Ignored` for events that need no internal action (a "pending"
notification). Forward `idempotency_key` so a re-map can't double-apply. Never mutate integrations' tables.

## Not a contract
- The 12 generated CRUD endpoints per entity are convenience scaffolding. Do **not** insert an event or
  flip a status through the generic PATCH surface — it bypasses the dedup, the mapping, and the outbox
  staging. Use `IntegrationsWriteService`.
- `// <<< CUSTOM` blocks preserve local edits only; not a cross-module extension point.

## Invariants a consumer must not break
- One event per `(connector, external_id)`; `receive_event` is the only intake; a webhook retry never
  re-maps (no double-applied payment).
- The connector must be active; the lifecycle event is durable.
- Integrations NEVER writes a module's tables directly — it maps through the module's write path via the port.
