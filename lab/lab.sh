#!/usr/bin/env bash
# Wazuh LAB helper. Local lab only — every port is bound to 127.0.0.1.
#
#   ./lab.sh setup    clone official wazuh-docker v4.14.9, generate certs, admin.env
#   ./lab.sh up       start manager/indexer/dashboard + 2 agents, then stop lab-db-01
#   ./lab.sh users    create the read-only API + indexer identities -> readonly.env
#   ./lab.sh verify   curl demo: read-only users can read, writes are denied
#   ./lab.sh alerts [ssh|fim|sudo|injection|all]   generate real alerts
#   ./lab.sh status   containers + agent list
#   ./lab.sh down     stop the lab (keeps data);  ./lab.sh nuke  also deletes volumes
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_DIR="$LAB_DIR/wazuh-docker"
UPSTREAM_TAG="v4.14.9"
UPSTREAM_COMMIT="56ece955b1107b7b62823afae5b7057e1dab9d98"
SINGLE_NODE="$UPSTREAM_DIR/single-node"
CERTS_DIR="$SINGLE_NODE/config/wazuh_indexer_ssl_certs"

compose() { docker compose --project-directory "$LAB_DIR" -f "$LAB_DIR/compose.yaml" "$@"; }
log() { printf '\033[1;34m[lab]\033[0m %s\n' "$*"; }

cmd_setup() {
  if [ ! -d "$UPSTREAM_DIR/.git" ]; then
    log "cloning wazuh-docker $UPSTREAM_TAG"
    git clone -q --depth 1 --branch "$UPSTREAM_TAG" https://github.com/wazuh/wazuh-docker "$UPSTREAM_DIR"
  fi
  local head; head="$(git -C "$UPSTREAM_DIR" rev-parse HEAD)"
  [ "$head" = "$UPSTREAM_COMMIT" ] || { echo "unexpected upstream commit $head" >&2; exit 1; }

  # The generator leaves the cert dir root-owned and unreadable for us, so the
  # public root CA is read through a throwaway container.
  mkdir -p "$LAB_DIR/certs"
  read_root_ca() {
    docker run --rm -v "$CERTS_DIR:/c:ro" --entrypoint cat \
      wazuh/wazuh-certs-generator:0.0.4 /c/root-ca.pem > "$LAB_DIR/certs/root-ca.pem" 2>/dev/null
  }
  if ! read_root_ca; then
    log "generating indexer/manager/dashboard certificates"
    (cd "$SINGLE_NODE" && docker compose -f generate-indexer-certs.yml run --rm generator)
    read_root_ca
  fi

  # Bootstrap (admin) credentials = upstream demo defaults, read from the
  # upstream compose file so no password literal lives in this repo.
  if [ ! -f "$LAB_DIR/admin.env" ]; then
    local f="$SINGLE_NODE/docker-compose.yml"
    umask 077
    {
      echo "# LAB bootstrap credentials (upstream demo defaults). Used only by lab scripts."
      echo "WAZUH_API_ADMIN_USER=$(grep -m1 'API_USERNAME=' "$f" | cut -d= -f2-)"
      echo "WAZUH_API_ADMIN_PASSWORD='$(grep -m1 'API_PASSWORD=' "$f" | cut -d= -f2-)'"
      echo "INDEXER_ADMIN_USER=$(grep -m1 'INDEXER_USERNAME=' "$f" | cut -d= -f2-)"
      echo "INDEXER_ADMIN_PASSWORD='$(grep -m1 'INDEXER_PASSWORD=' "$f" | cut -d= -f2-)'"
    } > "$LAB_DIR/admin.env"
    log "wrote admin.env (gitignored, mode 600)"
  fi
}

wait_for() {  # wait_for <description> <command...>
  local what="$1"; shift
  for _ in $(seq 1 90); do
    if "$@" >/dev/null 2>&1; then log "$what is up"; return 0; fi
    sleep 5
  done
  echo "timeout waiting for $what" >&2; return 1
}

api_admin_token() {
  # shellcheck disable=SC1091
  set -a; . "$LAB_DIR/admin.env"; set +a
  curl -sk -u "$WAZUH_API_ADMIN_USER:$WAZUH_API_ADMIN_PASSWORD" -X POST \
    "https://127.0.0.1:55000/security/user/authenticate?raw=true"
}

agents_active() {  # all named agents report status=active
  local token; token="$(api_admin_token)"
  local body; body="$(curl -sk -H "Authorization: Bearer $token" \
    "https://127.0.0.1:55000/agents?select=name,status&limit=50")"
  for name in "$@"; do
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); n=sys.argv[2]
sys.exit(0 if any(a["name"]==n and a["status"]=="active" for a in d["data"]["affected_items"]) else 1)' "$body" "$name" || return 1
  done
}

cmd_up() {
  [ -f "$LAB_DIR/admin.env" ] || cmd_setup
  compose up -d
  wait_for "Wazuh API" bash -c "[ -n \"\$(cd '$LAB_DIR' && ./lab.sh _token)\" ]"
  wait_for "Wazuh indexer" curl -sf --cacert "$LAB_DIR/certs/root-ca.pem" \
    --resolve wazuh.indexer:9200:127.0.0.1 https://wazuh.indexer:9200 -o /dev/null -w '' \
    -u "$(. "$LAB_DIR/admin.env"; echo "$INDEXER_ADMIN_USER:$INDEXER_ADMIN_PASSWORD")"
  wait_for "agents lab-web-01 + lab-db-01" agents_active lab-web-01 lab-db-01
  log "stopping lab-db-01 to simulate a disconnected agent"
  docker stop lab-db-01 >/dev/null
  log "dashboard: https://localhost (lab only)"
}

cmd_status() {
  compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
  local token; token="$(api_admin_token)"
  curl -sk -H "Authorization: Bearer $token" \
    "https://127.0.0.1:55000/agents?select=id,name,status,os.name,version&limit=50" |
    python3 -c 'import json,sys
for a in json.load(sys.stdin)["data"]["affected_items"]:
    print("  agent %s  %-16s %-16s %s" % (a["id"], a["name"], a["status"], a.get("os", {}).get("name", "")))'
}

case "${1:-}" in
  setup)  cmd_setup ;;
  up)     cmd_up ;;
  users)  python3 -I "$LAB_DIR/scripts/bootstrap_readonly.py" ;;
  verify) bash "$LAB_DIR/scripts/verify_readonly.sh" ;;
  alerts) bash "$LAB_DIR/scripts/gen_alerts.sh" "${2:-all}" ;;
  status) cmd_status ;;
  down)   compose down ;;
  nuke)   compose down -v ;;
  _token) api_admin_token ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
