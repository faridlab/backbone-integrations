# backbone-integrations — PRD

Platform (Tier 5) · the **connector hub** · posts no GL · the plan's recommended next integration.

## Why
An Indonesia retail SMB feels the most day-one friction at the **edges**: a payment gateway
(Midtrans/Xendit) notifying that an order was paid, a marketplace (Tokopedia/Shopee) pushing new orders, a
bank feed, a courier's status updates. `backbone-integrations` is the connector hub: it receives an
external provider event, records it idempotently, and maps it to an **internal action** through the target
module's PUBLIC contract — a settled payment → `backbone-payment`, a marketplace order → `backbone-selling`,
a bank line → `backbone-banking`. It never reaches into a module's internals (tier5-deferred §7, §10.3).

## Scope (KEEP — tier5-deferred.md §7)
- **IntegrationConnector** — a configured connection to a provider: kind (payment gateway / marketplace /
  bank feed / courier), direction, active flag. Unique per (company, provider).
- **IntegrationEvent** — one inbound provider event, deduped on **(connector, external_id)** (webhooks are
  at-least-once), with its outcome: `mapped` (an internal record was created — the audit link), `ignored`
  (no internal action needed — e.g. a "pending" notification), or `failed` (with the reason).
- **The receive engine** — `receive_event` dedups, maps via a `TargetPort` (the target module's write
  path), and records the outcome; the lifecycle event is durable.
- **The flagship connector** — payment gateway → `backbone-payment` (a settled notification becomes a
  customer receipt), proven against the REAL module.

## Non-goals (CUT / DEFER — tier5-deferred.md §7)
- The concrete provider adapters (the Midtrans HMAC-verified webhook parser, the Tokopedia OAuth client) —
  the composing service parses/verifies and hands `receive_event` a structured payload.
- Outbound push (marking an order shipped on the marketplace) — structured later; inbound is the day-one need.
- Credential storage / rotation.

## Success criteria
- An inbound provider event maps **exactly once** under at-least-once webhook retry (no double-applied
  payment), and the lifecycle event is durable; dedup is **per connector** (providers reuse ids).
- A settled-payment notification becomes a real payment in backbone-payment (proven against the REAL
  module); a "pending" notification is intentionally ignored.
- Zero normal Cargo edge; survives a full codegen regen (§5). Posts no GL.
