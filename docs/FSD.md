# backbone-integrations — FSD

## Entities
IntegrationConnector (`company_id`, `provider`, `kind`, `direction`, `is_active`; unique `(company_id,
provider)`) · IntegrationEvent (`company_id`, `connector_id` FK, `event_type`, `external_id` (raw
notification id — audit), `business_key` (the dedup key — order ref + terminal state), `status`, `payload`,
`mapped_ref_type?`/`mapped_ref_id?` logical, `error_detail?`; unique `(connector_id, business_key)`; index
`(company_id, status)`). Enums: ConnectorKind {payment_gateway, marketplace, bank_feed, courier},
ConnectorDirection {inbound, outbound, both}, IntegrationStatus {received, mapped, ignored, failed}.

## Write path (`IntegrationsWriteService`, hand-authored, user-owned)
- `register_connector(NewConnector)` → a provider connection (one per company/provider)
- `receive_event(InboundEvent, &dyn TargetPort, &dyn IntegrationEventSink)` → dedup on (connector,
  business_key); map via the target write path → `mapped`/`ignored`/`failed` + **stage the lifecycle event
  in the same tx (outbox)** + publish; returns `ReceiveOutcome {event_id, status, mapped_ref_id, duplicate}`

### Failure recovery (completeness council 2026-07-11)
- `failures(connector_id) -> Vec<FailedEvent>` → the failure report: every `status='failed'` event with its
  keys + `error_detail`, so an operator sees which provider events didn't book (and why) from the public API,
  without querying the module's internals.
- `retry_failed(connector_id, &dyn TargetPort, &dyn IntegrationEventSink) -> usize` → re-drive the connector's
  failed events through the target after the cause is fixed. Re-invokes the port under the SAME `business_key`
  idempotency (so it can't double-apply); a still-`failed` event that now maps transitions `failed → mapped`
  (CAS-gated) + stages `IntegrationEventMapped` + publishes. Returns the count newly mapped. This is the
  recovery path the intake dedup would otherwise weld shut — a re-delivered webhook dedups and never re-maps.

Errors: `IntegrationError {Db, NotFound, InvalidState, Invalid, MappingRejected}`.

## Seam (port — zero normal Cargo edge)
- **Map → target module (proven, ISEAM-1):** an inbound event maps to an internal record via `TargetPort`
  (`MapOutcome::Mapped | Ignored`), implemented over the target's write path — proven: a Midtrans
  settled-payment notification → REAL backbone-payment `create_payment` (a customer receipt). The forwarded
  `idempotency_key` is the business key. Integrations never imports the target module.
- **Outbound:** `IntegrationEventMapped`/`Failed`/`Ignored` staged to the outbox + published.

## Test oracle
`integrations_golden_cases` (5: IGC-1 settled maps, IGC-2 retry idempotent, IGC-3 pending ignored, IGC-4
unmappable fails, IGC-5 failures report + retry re-drives a stuck payment),
`integrity_probes` (5: IIP-1 external_id required, IIP-2 inactive connector rejected, IIP-3 dedup
per-connector, IIP-4 lifecycle event durable, IIP-5 second settled notification dedups),
`integrations_payment_seam` (1: ISEAM-1 settled notification becomes a REAL payment) + §5 round-trip.
**11 tests.**

> The generated `integration_tests.rs` hits an external HTTP server and is environmental scaffolding, not
> part of this module's correctness gate.
