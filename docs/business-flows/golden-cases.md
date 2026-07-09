# backbone-integrations — business flows & golden cases

## Flow: provider webhook → dedup → map (durably)
```
receive_event (provider webhook, at-least-once)
   │
   ▼  dedup on (connector, business_key) — a retry OR a 2nd notification for the same order → duplicate=true
   │        (a NEW business action — a different order+state — maps as new)
   │
   ▼  INSERT received → map via TargetPort (the target module's write path)
   │        ├─ Mapped(ref) → status=mapped + STAGE IntegrationEventMapped (same tx) → commit
   │        ├─ Ignored(reason) → status=ignored (a "pending" notification — no internal action)
   │        └─ Err → status=failed + reason
   │
   └▶ IntegrationEventMapped → the internal record exists (a real payment / sales order)
```
Posts NO GL. The composing service verifies + parses the provider webhook; this module owns the lifecycle.

## Golden cases (`tests/integrations_golden_cases.rs`)
- **IGC-1 — settled maps.** A settled notification → mapped, an internal ref recorded, `IntegrationEventMapped`.
- **IGC-2 — retry idempotent.** The same event twice → mapped once (no double-applied payment).
- **IGC-3 — pending ignored.** A "pending" notification → `ignored`, no internal action, reason recorded.
- **IGC-4 — unmappable fails.** A rejected map → `failed` + reason + `IntegrationEventFailed`.
- **IGC-5 — failures report + retry.** A settled notification whose target is DOWN → `failed`; `failures()`
  lists it with its reason; `retry_failed` with a healthy target re-drives it → a REAL payment, `failures()`
  drains to empty. Proven-by-revert. (completeness council 2026-07-11)

## Integrity probes (`tests/integrity_probes.rs`)
- **IIP-1 — external_id required.**
- **IIP-2 — inactive connector rejected.**
- **IIP-3 — dedup per-connector.** The same external id on two connectors both map (providers reuse ids).
- **IIP-4 — lifecycle event durable.** With the in-proc publish lost, `IntegrationEventMapped` is staged in
  the outbox.
- **IIP-5 — second settled notification dedups.** Two distinct settled notifications for one order (same
  `business_key`, different notification id) → mapped once (payment applied once). Proven-by-revert.

## Seam (`tests/integrations_payment_seam.rs`)
- **ISEAM-1 — settled notification becomes a REAL payment.** A Midtrans settled notification → `TargetPort`
  over REAL backbone-payment → a genuine customer receipt (type/amount/reference match); the event records
  the link back. Zero normal Cargo edge.

## §5 round-trip (`scripts/integrations_payment_seam_roundtrip.sh`)
Regen (`--force`) leaves the seam files byte-identical; the oracle + seam re-run green.
