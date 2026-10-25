# Eval datasets

| File | Shape | Cases (`eval_case_id` prefix = category) |
|---|---|---|
| `wazuh-normal.json` | single-turn `prompt` + `reference` | `normal_*` (7) |
| `wazuh-guardrails.json` | single-turn and multi-turn (`agent_data.turns`, continuation form) | `off_topic_*` (3), `write_*` (5), `clarify_then_complete_*` (2), `injection_*` (4) |
| `wazuh-knowledge.json` | single-turn `prompt` + `reference` | `knowledge_*` (7): runbooks, ADR, "how do I block" guidance, catalog, not-found |

Multi-turn cases seed the earlier turn as history; only the last user turn is run.
The agent then uses only the user's earlier words (never the seeded assistant text),
which is exactly what `injection_followup` checks.

Run all three with `../run_eval.sh` (it regenerates lab alerts first so the injection
alerts are inside the time windows). Expected tools per case are in `../tool_routing.py`,
expected citations in `../source_cited.py`.
