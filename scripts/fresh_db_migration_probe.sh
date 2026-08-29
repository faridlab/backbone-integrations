#!/usr/bin/env bash
# Fresh-database migration probe: apply this module's migrations in filename order
# (ON_ERROR_STOP=1 so a failure aborts mid-file), then the banking + payment legs a
# cross-module seam needs, then verify the expected relations, enums, and company-RLS
# policies exist. A failure at any file leaves the scratch database half-applied by
# construction — the script reports the exact stopping point so nothing silent ships.
#
# Usage: fresh_db_migration_probe.sh [db-name]
# Environment: scratch container on 127.0.0.1:5433, user/password postgres/postgres.
set -uo pipefail
cd "$(dirname "$0")/.."

PSQL=${PSQL:-/opt/homebrew/opt/libpq/bin/psql}
HOST=127.0.0.1
PORT=5433
DB="${1:-integrations_migration_probe_$(date +%Y%m%d%H%M%S)}"
export PGPASSWORD=postgres

psql_q() { "$PSQL" -h $HOST -p $PORT -U postgres "$@"; }

echo "== creating fresh database: $DB"
psql_q -c "DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1
psql_q -c "CREATE DATABASE $DB" >/dev/null || { echo "FAIL: cannot create $DB"; exit 1; }

apply_dir() {
  local dir="$1" label="$2"
  local failed=0
  for f in $(ls "$dir"/*.up.sql | sort); do
    if ! out=$(psql_q -d "$DB" -v ON_ERROR_STOP=1 -f "$f" 2>&1); then
      echo "HALF-APPLIED: $label stopped at $(basename "$f"):"
      echo "$out" | grep -v NOTICE | tail -5
      return 1
    fi
  done
  echo "ok: $label ($(ls "$dir"/*.up.sql | wc -l | tr -d ' ') files)"
  return 0
}

status=0
apply_dir migrations "integrations" || status=1
[[ -d ../backbone-banking/migrations ]] && apply_dir ../backbone-banking/migrations "banking" || status=1
[[ -d ../backbone-payment/migrations ]] && apply_dir ../backbone-payment/migrations "payment" || status=1
[[ $status -ne 0 ]] && { echo "FAIL: migrations incomplete (half-applied state above)"; exit 1; }

echo "== relations in schema integrations"
psql_q -d "$DB" -tAc "SELECT tablename FROM pg_tables WHERE schemaname='integrations' ORDER BY 1"
echo "== enums created by this module (public-schema convention)"
psql_q -d "$DB" -tAc "SELECT typname FROM pg_type WHERE typname IN ('connector_kind','connector_direction','integration_status','o_auth_provider','integration_account_status') AND typtype='e' ORDER BY 1"
echo "== RLS policies on integration_accounts (company fence)"
psql_q -d "$DB" -tAc "SELECT policyname FROM pg_policies WHERE schemaname='integrations' AND tablename='integration_accounts' ORDER BY 1"
echo "== seam relations present"
psql_q -d "$DB" -tAc "SELECT to_regclass('payment.payment_entries'), to_regclass('banking.bank_accounts')"

echo "== asserting the OAuth account surface exists (table, enums, RLS fence)"
probe_fail=0
tbl=$(psql_q -d "$DB" -tAc "SELECT to_regclass('integrations.integration_accounts')")
[[ "$tbl" == "integrations.integration_accounts" ]] || { echo "FAIL: integrations.integration_accounts missing (to_regclass='$tbl')"; probe_fail=1; }
for e in o_auth_provider integration_account_status; do
  # This module's convention creates enums unqualified (public schema, like connector_kind).
  n=$(psql_q -d "$DB" -tAc "SELECT count(*) FROM pg_type WHERE typname='$e'")
  [[ "$n" == "1" ]] || { echo "FAIL: enum $e missing"; probe_fail=1; }
done
rls=$(psql_q -d "$DB" -tAc "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='integrations' AND c.relname='integration_accounts'")
pol=$(psql_q -d "$DB" -tAc "SELECT count(*) FROM pg_policies WHERE schemaname='integrations' AND tablename='integration_accounts'")
[[ "$rls" == "t" && "$pol" -ge 1 ]] || { echo "FAIL: company RLS fence on integration_accounts (rls=$rls policies=$pol)"; probe_fail=1; }

echo "== columns of integration_accounts"
psql_q -d "$DB" -c "\d integrations.integration_accounts" 2>/dev/null | sed -n '3,30p'

[[ $probe_fail -eq 0 ]] || { echo "FAIL: migration probe assertions failed on $DB"; exit 1; }

echo "OK: fresh-db migration probe complete on $DB"
