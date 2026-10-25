#!/usr/bin/env bash
# Run both eval datasets against the live LAB and print the result tables.
#   agent/tests/eval/run_eval.sh            (from anywhere)
# Needs: lab up + readonly users, wazuh-mcp on :8020, GEMINI_API_KEY in .env.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$AGENT_DIR/../lab/lab.sh"
cd "$AGENT_DIR"

curl -s -o /dev/null -X POST http://127.0.0.1:8020/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' \
  || { echo "wazuh-mcp is not running on :8020 (cd wazuh_mcp && uv run wazuh-mcp)"; exit 1; }

# Fresh lab data inside the 24h windows; injection lines last so they are newest.
"$LAB" alerts all
echo "waiting 20 s for the alerts to be indexed..."
sleep 20

# Low concurrency/qps: the agent and both LLM judges share the Gemini quota.
for ds in normal guardrails knowledge; do
  agents-cli eval run \
    --dataset "tests/eval/datasets/wazuh-$ds.json" \
    --config tests/eval/eval_config.yaml \
    --output "artifacts/grade_results/$ds" \
    --app-name wazuh_agent --concurrency 2 --qps 2
done

uv run python tests/eval/summarize.py artifacts/grade_results/{normal,guardrails,knowledge}
