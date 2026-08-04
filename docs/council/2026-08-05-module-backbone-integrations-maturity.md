<!-- 2026-08-05 | repo: module | unit: backbone-integrations | focus: maturity | roster: chair, skeptic, steelman, yagni-business, ddd-bounded-context, contract-seat, domain-expert -->

# Council — module:backbone-integrations — focus: maturity

## Best call
**NOT complete.** Split the verdict: the **design** is mature for a first-integration tier-5 bar (dedup, TargetPort ACL, same-tx outbox, RLS fence, CAS retry all real); the **artifact** is incomplete and must not be promoted. The single gating move: land a CI gate on every push running `cargo check` + golden tests **rewired through `IntegrationsModule::builder().build()`**, and **fix the codegen template so CUSTOM-registered service fields land inside the module struct** (the dangling block at lib.rs:180-184 proves there is no slot today — recurrence is structural, not one-time). Status until that gate is green: *design-complete, artifact-incomplete*.
- Residual negative value: ~1–3 days of eng effort to land the gate + template slot; the module stays **unproven-in-deployment** (zero consumers, zero references) so even post-gate "complete" caps at "builds and passes its own tests," not "validated by a real integration"; the broader 25-file scaffold-churn tax (YAGNI) is unaddressed by this move.
- Reversibility: **easy** — all three sub-parts (parse fix, template slot, CI gate) are reversible; status flips to "complete" the moment the gate goes green.
- What would flip this: a real consumer successfully integrating against `IntegrationsModule::builder().build()` (proves the artifact, not the design), OR the owner explicitly adopting a two-tier definition ("design-complete" tracked separately from "artifact-complete").

## Disagreement map
- **Design-maturity vs artifact-maturity** — Steelman says the design elements clear the tier-5 bar so it's effectively mature; Skeptic says maturity is being scored against a stale idealized tree in reviewers' heads, not the non-building checked-out code, and the tests were never routed through the builder so they prove nothing about the broken path. **Crux: does "complete" mean design-complete or artifact-complete?** I own it: an artifact that does not compile has no consumer-reliable "complete."
- **One-time mechanical fix vs structural codegen recurrence** — Steelman treats the regen damage as localized and mechanical; Skeptic + YAGNI treat the 25-file churn as the standing maintenance tax of the full scaffold, and the missing struct-slot proves the next regen re-breaks it. **Crux: is there a template slot preventing recurrence?** Verified answer: no (lib.rs:180-184 dangles precisely because there isn't one).
- **Generic CRUD on `IntegrationEvent`: deferrable scaffold vs invariant-bypass footgun** — Steelman treats it as tier-5-deferable breadth; YAGNI says events are *produced* by the idempotent receive state machine, so exposing create/update/patch/upsert/bulk_create invites bypassing the dedup invariant — over-built AND dangerous. **Crux: does the CRUD surface let a caller skip the state machine?** It does.

## Recommendations (ranked by leverage)
| # | Move | Leverage | Residual negative | Reversibility | Evidence to flip |
|---|------|----------|-------------------|---------------|------------------|
| 1 | Gate promotion on CI (`cargo check` + golden tests via the builder) AND add the codegen struct-slot for CUSTOM service fields | Highest — kills recurrence, restores the load-bearing evidence Skeptic proved false | ~1–3 days; scaffold-churn tax untouched | Easy | A consumer integrating green against the builder |
| 2 | Rewire IGC-1..IGC-5 to construct through `IntegrationsModule::builder().build()`, not `IntegrationsWriteService::new(pool)` | Restores the only proof surface for the broken path | Tests still don't cover egress/credentials (none exist) | Easy | A test that catches a real builder regression pre-merge |
| 3 | Mechanical fix: move the dangling field back inside `IntegrationsModule` (lib.rs:65-70) so the crate compiles | Unblocks build today | Alone, recurrence is certain on next regen; masks the template gap | Easy | n/a — necessary regardless |
| 4 | Remove the `pub use domain::entity::*` glob; expose only port trait + DTOs (Contract-Seat) | Stops consumers depending on internals; shrinks churn surface | None material for an unconsumed module | Easy | A consumer that legitimately needs an internal value object |
| 5 | Drop generic CRUD on `IntegrationEvent`; keep only list/get + the receive/retry state machine (YAGNI) | Removes the dedup-bypass footgun at the source | May need a read-only admin route re-added later | Easy | A real admin use case for hand-creating events |

## Maturity scorecard (focus = maturity)
| Seat | Axis | Score (1–5) | One sentence why |
|------|------|-------------|------------------|
| DDD-Bounded-Context | language consistent + contracts stable under change | 2 | `IntegrationEvent` is overloaded (persisted row entity vs outbox event enum) and `MapRequest.idempotency_key`'s doc contradicts its `business_key` call site — the language is not stable. |
| Contract-Seat | explicit/minimal outward contract, internals free behind it | 2 | `pub use domain::entity::*` leaks the entire entity+value-object layer at root, DTOs embed internal enums, and the write service struct is `pub use`'d — the contract is neither explicit nor minimal. |
| Domain-Expert | ubiquitous language end-to-end + model represents every real state/rule | 2 | `direction: outbound\|both` has no egress path and no credential store is modeled — a "configured connection" cannot represent its own API key, so half the modeled states are unreachable. |
| YAGNI/Business | removes concrete pain THIS month at business scale, not premature abstraction | 2 | Zero consumers exist, yet 25+ scaffold files (CRUD on both entities, versioning middleware, bulk ops, saga, seeders) churn on every regen for a single inbound gateway — premature breadth, and CRUD-on-events is a footgun. |

## Parking lot
- `received`-strand reaper deferral (ADR-001) — raised by Steelman, scope: root (reaper belongs upstream/out-of-module; tier-5 deferral accepted).
- `outbound`/`both` egress path — raised by Domain-Expert, scope: this module (next milestone; out of focus for "is what's here mature").
- Credential store model (provider/kind/direction/is_active needs secrets) — raised by Domain-Expert, scope: this module (next milestone).
- Scaffold breadth (example_saga_workflow, bulk_operations, subscriptions, seeders) — raised by YAGNI, scope: root (codegen default surface, not this module's design).

---

## File anchors
- src/lib.rs — struct (65-70), build() literal (165-171), dangling field causing the parse error (180-184), entity glob leak (29).
- src/exports/services.rs — empty CUSTOM template where `IntegrationsQueryService` lived (13-15).
