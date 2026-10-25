#!/usr/bin/env bash
# Start the demo (LAB only): Wazuh lab + read-only MCP server in the background,
# fresh alerts, health table. asset_agent and the playground are NOT started here:
# run them yourself in two foreground terminals (commands printed at the end), so
# the A2A log lines stay visible and asset_agent can be stopped with Ctrl+C.
#
#   scripts/demo-up.sh            # idempotent; scripts/demo-down.sh stops everything
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
mkdir -p "$RUN"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
listening() { lsof -t -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

[ -f "$ROOT/.env" ] || { echo "missing $ROOT/.env (copy .env.example, set GEMINI_API_KEY)"; exit 1; }

step "1/5 Wazuh lab (docker compose, 127.0.0.1 only)"
"$ROOT/lab/lab.sh" up

step "2/5 Read-only identities"
if [ -f "$ROOT/lab/readonly.env" ]; then
  echo "lab/readonly.env exists (assistant_api_ro / assistant_idx_ro)"
else
  "$ROOT/lab/lab.sh" users
fi

step "3/5 MCP server wazuh_mcp on 127.0.0.1:8020 (background)"
if listening 8020; then
  echo "already running"
else
  (cd "$ROOT/wazuh_mcp" && setsid nohup uv run wazuh-mcp >"$RUN/wazuh-mcp.log" 2>&1 & echo $! >"$RUN/wazuh-mcp.pid")
  for _ in $(seq 1 60); do listening 8020 && break; sleep 1; done
  listening 8020 || { echo "wazuh-mcp did not start, see $RUN/wazuh-mcp.log"; exit 1; }
  echo "started (log: .run/wazuh-mcp.log)"
fi

step "4/5 Fresh alerts: ssh brute force + prompt injection"
"$ROOT/lab/lab.sh" alerts ssh
"$ROOT/lab/lab.sh" alerts injection

step "5/5 Health check (waits up to 120 s for indexing / agent status)"
set +e
(cd "$ROOT" && uv run -q --project wazuh_mcp python -I scripts/health.py --wait 120)
health=$?
set -e

cat <<EOF
Dashboard (optional): https://localhost

Now open two VS Code terminals and run (foreground, Ctrl+C stops them):

  Terminal 1 — asset_agent (A2A server, :8030):
    cd $ROOT/asset_agent && uv run asset-agent

  Terminal 2 — playground (wazuh_agent, :8502):
    cd $ROOT/agent && agents-cli playground --port 8502

Then open http://127.0.0.1:8502 and select wazuh_agent.
Agent card: curl -s http://127.0.0.1:8030/.well-known/agent-card.json | python3 -m json.tool
EOF
exit "$health"
