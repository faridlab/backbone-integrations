#!/usr/bin/env bash
# §5 round-trip: the connector hub (idempotent receive + map/ignore + durable event) survives regen.
set -euo pipefail
cd "$(dirname "$0")/.."
export DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5433/backbone_integrations}"
SEAM=(src/application/service/integrations_ports.rs src/application/service/integrations_events.rs src/application/service/integrations_write_service.rs)
before=$(shasum "${SEAM[@]}")
echo "== regenerating (--force) =="
metaphor schema schema generate --force >/dev/null
after=$(shasum "${SEAM[@]}")
if [[ "$before" != "$after" ]]; then echo "FAIL: seam files changed across regen"; diff <(echo "$before") <(echo "$after"); exit 1; fi
echo "OK: seam files byte-identical across regen"
echo "== re-running the oracle + seam =="
cargo test --test integrations_golden_cases --test integrity_probes --test integrations_payment_seam 2>&1 | grep -E "test result"
echo "OK: §5 round-trip holds"
