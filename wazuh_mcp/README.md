# wazuh_mcp — read-only MCP server for the Wazuh LAB

mcp Python SDK 2.x `MCPServer` (the former FastMCP), Streamable HTTP at
`http://127.0.0.1:8020/mcp`. Credentials: the read-only identities from
`lab/readonly.env` (created by `lab/lab.sh users`); override with env vars.

```bash
cd wazuh_mcp
uv sync
uv run wazuh-mcp                       # MCP_HOST=127.0.0.1 MCP_PORT=8020 by default
uv run pytest tests/unit               # 76 offline tests (fake Wazuh via httpx.MockTransport)
uv run pytest tests/integration -m live   # against the running lab
```

## Tools (all `readOnlyHint=true`, structured output)

| Tool | Source | Returns (trimmed) | Caps |
|---|---|---|---|
| `list_agents(status="all", limit=20)` | API `/agents` (manager 000 excluded) + `/agents/summary/status` | id, name, status, ip, os, version, last keepalive, groups; status counts | limit ≤ 50 |
| `list_alerts(since="24h", min_level=0, agent=None, limit=20)` | indexer `wazuh-alerts-*/_search`, newest first | time, agent, rule id/level/severity/description, MITRE, srcip/srcuser/command, FIM path/event, cleaned `full_log`, `injection_suspected` | limit ≤ 50, since ≤ 30d, full_log ≤ 300 chars |
| `alert_stats(group_by="rule", since="24h", top=10)` | indexer terms aggregation | buckets `{key, count, max_level, label}`, total, other_count | group_by ∈ rule/agent/level/group/srcip/mitre/tactic, top ≤ 20 |
| `explain_rule(rule_id)` | API `/rules`, `/mitre/techniques`, `/mitre/tactics` + indexer count | level, severity, plain-English summary (e.g. correlation 8× in 120 s), conditions, MITRE technique + tactic, compliance, 24h activity | 3 techniques |
| `sca_summary(agent)` | API `/sca/{id}`, `/sca/{id}/checks/{policy}?result=failed` | score, pass/fail/invalid per policy, 5 failed checks | 10 policies |

## Security

- **LAB only**: API/indexer URLs must resolve to an allowlisted host
  (`127.0.0.1, localhost, wazuh.manager, wazuh.indexer`); otherwise the server refuses to start.
- **Read-only in three layers**: RBAC of the lab users → clients with no write
  methods (API: GET on `/agents`, `/rules`, `/sca/`, `/mitre/` only; indexer: `_search`
  on `wazuh-alerts-*` only) → no write tools. Tested in `tests/unit/test_read_only.py`.
- **Untrusted alert text** (`untrusted.py`): ANSI/control/zero-width/bidi characters
  removed, length capped, prompt-injection phrases flagged (`injection_suspected`);
  every alert list carries an `untrusted_notice`.
- **Input validation**: `since`, `agent`, `group_by`, `status`, `rule_id` are checked
  against regexes/allowlists before reaching a query or URL path.
- **TLS**: indexer cert verified against the lab CA *and* its name `wazuh.indexer`
  (SNI override while dialing 127.0.0.1); the API's self-signed cert is the only trust anchor.
- Errors are short `ToolError` messages; passwords never appear in logs, errors or `repr`.
