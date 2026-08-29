#!/usr/bin/env bash
# Port-discipline gate: the OAuth flow must reach the credential store through an
# injectable edge-free port only. This module must carry ZERO references to the
# credential store's home crate anywhere in its shipped source, and no Cargo
# dependency edge to it (a dev-dependency for tests is allowed, as with other
# test-only seams).
#
# Fails (exit 1) listing every offending occurrence; passes silently (exit 0).
set -euo pipefail
cd "$(dirname "$0")/.."

status=0

# 1. No credential-store crate path in any shipped CODE. Doc comments that
#    explain the placement rule may name the store's home crate in prose (the
#    port file's header records the ADR rationale); what the gate forbids is any
#    import path, type reference, or Cargo edge — the things a compiler would
#    need the crate for. Comment lines are stripped before matching.
hits=$(grep -rn -E 'backbone[-_]sapiens' src/ | grep -v -E '^[^:]+:[0-9]+:\s*//' || true)
if [[ -n "$hits" ]]; then
  echo "FAIL: credential-store crate referenced in shipped source:" >&2
  echo "$hits" >&2
  status=1
fi

# 2. No credential-store crate in the runtime [dependencies] section of Cargo.toml.
#   (Scans from the [dependencies] header up to the next section header.)
dep_hit=$(awk '/^\[dependencies\]/{flag=1;next} /^\[/{flag=0} flag && /backbone[-_]sapiens/' Cargo.toml || true)
if [[ -n "$dep_hit" ]]; then
  echo "FAIL: credential-store crate declared as a runtime dependency:" >&2
  echo "$dep_hit" >&2
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "OK: zero credential-store references in src/ and no runtime dependency edge"
fi
exit $status
