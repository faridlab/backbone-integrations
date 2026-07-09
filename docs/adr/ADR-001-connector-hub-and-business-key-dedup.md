# ADR-001 — The connector hub, business-key dedup, and durable event processing

Status: accepted · 2026-07-11 · Platform (Tier 5; posts no GL)

## Context
An Indonesia retail SMB feels the most day-one friction at the edges — a payment gateway notifying an order
was paid, a marketplace pushing orders, a bank feed. Integrations is the connector hub: it receives a
provider event and maps it to an internal action through the target module's public write path. It never
reaches into a module's internals (tier5-deferred §7, the plan's recommended next integration).

## Decision
1. **Idempotency keys on the BUSINESS action, not the notification id.** A gateway sends multiple
   notifications per order (pending → settled), each with a different notification id but the same order
   ref; deduping on the notification id would apply the payment TWICE. The dedup key is `business_key` (the
   order/transaction ref + terminal state); `external_id` is the raw notification id (audit). The forwarded
   `idempotency_key` is the business key, so the target dedups the effect too (maturity council 2026-07-11).
2. **Mapping is a PORT, not a dependency.** An event maps via `TargetPort` — a settled payment →
   backbone-payment, an order → backbone-selling. Zero Cargo edge — proven by ISEAM-1 creating a REAL
   payment. Not every event needs an action: a "pending" notification is `Ignored`.
3. **The lifecycle event is DURABLE** — staged in the outbox in the same tx as the status update.
4. **Failures are first-class AND recoverable** — an unmappable event is `failed` with the reason +
   `IntegrationEventFailed`; `failures(connector_id)` exposes the failure report and
   `retry_failed(connector_id, target, sink)` re-drives failed events through the target under the same
   business-key idempotency (completeness council 2026-07-11) — the recovery the intake dedup would otherwise
   weld shut.
5. **Posts no GL.** The connector must be active before any event is processed.

## Consequences
- Turn integrations off and no external event enters; it is the one place provider traffic becomes internal
  actions. Proven vs REAL backbone-payment; durable across a lost publish; survives regen (§5).

## Parking lot (each with a gate)
- **Recycled/per-notification dedup double-applied a payment** — FIXED (maturity council 2026-07-11):
  deduped on `business_key` (order + state), not the notification id, and forward it as the target's
  idempotency key (IIP-5, proven-by-revert).
- **Stuck-failed event was invisible + un-retryable** — FIXED (completeness council 2026-07-11): a settled
  notification that failed to book was stranded `failed` forever (the re-delivery dedups). Added
  `failures()` (the report) + `retry_failed()` (re-drive under the same business key) — IGC-5, proven-by-revert.
- **Map/UPDATE non-atomicity + no reaper** — a crash after the payment is created but before the status
  UPDATE strands a real payment behind a `received` event; the dedup then blocks re-mapping. `retry_failed`
  recovers `failed` events; the `received`-strand case still needs a scheduled reaper on the same re-drive
  machinery. Gate: a `remap_pending` reaper reconciling via the idempotent target.
- **Concrete provider adapters (HMAC verify/parse), outbound push, credential storage** — deferred (PRD).
