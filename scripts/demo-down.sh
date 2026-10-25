#!/usr/bin/env bash
# Stop the demo cleanly: playground, asset_agent, MCP server, then the Wazuh lab
# containers. Lab data (volumes, certs, read-only users) is kept.
#
#   scripts/demo-down.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

stop_port() {  # stop_port <name> <port>: SIGTERM the listener, SIGKILL after 10 s
  local name="$1" port="$2" pids
  pids="$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | sort -u)"
  if [ -z "$pids" ]; then
    printf '  %-12s :%s not running\n' "$name" "$port"
    return
  fi
  kill $pids 2>/dev/null
  for _ in $(seq 1 10); do
    lsof -t -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 1
  done
  if lsof -t -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    kill -9 $pids 2>/dev/null
    printf '  %-12s :%s killed\n' "$name" "$port"
  else
    printf '  %-12s :%s stopped\n' "$name" "$port"
  fi
}

echo "==> Stopping processes"
stop_port playground 8502
stop_port asset_agent 8030
stop_port wazuh-mcp 8020
rm -f "$ROOT/.run/wazuh-mcp.pid"

echo "==> Stopping the Wazuh lab (data kept; 'lab/lab.sh nuke' would delete it)"
"$ROOT/lab/lab.sh" down
