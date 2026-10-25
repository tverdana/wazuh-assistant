#!/usr/bin/env bash
# curl demo: the assistant's read-only identities can read, every write is denied.
# Uses lab/readonly.env only (no admin credentials). Passwords are passed to curl
# via -K <(...) so they never appear on the command line / in `ps`.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a; . "$LAB_DIR/readonly.env"; set +a

# Wazuh API: self-signed cert issued for CN=wazuh.com -> pin its public key.
API_PIN="sha256//$(openssl x509 -in "$WAZUH_API_CA" -pubkey -noout |
  openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
API="https://127.0.0.1:55000"
# Indexer: cert for wazuh.indexer signed by the lab root CA -> full verification.
IDX="https://wazuh.indexer:9200"
IDX_TLS=(--cacert "$WAZUH_INDEXER_CA" --resolve wazuh.indexer:9200:127.0.0.1)

TOKEN="$(curl -s -k --pinnedpubkey "$API_PIN" -X POST \
  -K <(printf 'user = "%s:%s"\n' "$WAZUH_API_USER" "$WAZUH_API_PASSWORD") \
  "$API/security/user/authenticate?raw=true")"
[ -n "$TOKEN" ] && [ "${#TOKEN}" -gt 100 ] || { echo "API login failed"; exit 1; }

pass=0; fail=0
body="$(mktemp)"; trap 'rm -f "$body"' EXIT

show() {  # show <expected> <code> <label>
  local mark="OK  "; if [ "$2" = "$1" ]; then pass=$((pass + 1)); else mark="FAIL"; fail=$((fail + 1)); fi
  printf '%s %-58s -> HTTP %s (expected %s)\n' "$mark" "$3" "$2" "$1"
  printf '       %s\n' "$(tr -d '\n' < "$body" | cut -c1-150)"
}

api() {  # api <expected> <METHOD> <path> [data]
  local code
  code="$(curl -s -k --pinnedpubkey "$API_PIN" -o "$body" -w '%{http_code}' -X "$2" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    ${4:+-d "$4"} "$API$3")"
  show "$1" "$code" "API  $2 $3"
}

idx() {  # idx <expected> <METHOD> <path> [data]
  local code
  code="$(curl -s "${IDX_TLS[@]}" -o "$body" -w '%{http_code}' -X "$2" \
    -K <(printf 'user = "%s:%s"\n' "$WAZUH_INDEXER_USER" "$WAZUH_INDEXER_PASSWORD") \
    -H 'Content-Type: application/json' ${4:+-d "$4"} "$IDX$3")"
  show "$1" "$code" "IDX  $2 $3"
}

TODAY="$(date -u +%Y.%m.%d)"

echo "== Wazuh server API as $WAZUH_API_USER (role assistant_readonly) =="
api 200 GET    "/agents?select=id,name,status&limit=5"
api 200 GET    "/rules?rule_ids=5712&select=id,level,description"
api 200 GET    "/sca/001?limit=2&select=policy_id,name,pass,fail,score"
api 403 PUT    "/agents/restart?agents_list=001"
api 403 DELETE "/agents?agents_list=002&status=all&older_than=0s"
api 403 PUT    "/active-response?agents_list=001" '{"command":"!restart-wazuh"}'
api 403 POST   "/security/users" '{"username":"evil_admin","password":"Evil-Pass-123!"}'
api 403 PUT    "/manager/restart"

echo
echo "== Wazuh indexer as $WAZUH_INDEXER_USER (role assistant_alerts_read) =="
idx 200 GET    "/wazuh-alerts-*/_count"
idx 200 POST   "/wazuh-alerts-*/_search?size=0" \
  '{"query":{"range":{"timestamp":{"gte":"now-1h"}}},"aggs":{"rules":{"terms":{"field":"rule.id","size":8}}}}'
idx 403 POST   "/wazuh-alerts-4.x-$TODAY/_doc" '{"rule":{"description":"forged alert"}}'
idx 403 POST   "/wazuh-alerts-*/_delete_by_query" '{"query":{"match_all":{}}}'
idx 403 DELETE "/wazuh-alerts-4.x-$TODAY"
idx 403 GET    "/wazuh-monitoring-*/_search?size=1"
idx 403 GET    "/wazuh-states-inventory-users-*/_search?size=1"
idx 403 GET    "/_cat/indices"
idx 403 PUT    "/$WAZUH_INDEXER_USER"

echo
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
