# asset_agent — lab asset inventory over A2A

A separate process that serves the (fictional) lab inventory
[`asset_agent/inventory.json`](asset_agent/inventory.json) as an **A2A server**.
It is a deterministic ADK `Workflow` (one function node, no LLM) wrapped with ADK's
`to_a2a()` and an explicit `AgentCard`.

```bash
cd asset_agent
uv sync
uv run asset-agent                                   # http://127.0.0.1:8030
curl -s http://127.0.0.1:8030/.well-known/agent-card.json | python3 -m json.tool
uv run pytest -q                                     # 11 tests
```

| Host | Owner | Role | should_be_monitored | In Wazuh? |
|---|---|---|---|---|
| lab-web-01 | Web Platform team | nginx web front-end | yes | agent 001, active |
| lab-db-01 | Database team | PostgreSQL primary | yes | agent 002, disconnected |
| lab-backup-01 | Infrastructure team | backup server | yes | **no agent** (coverage gap) |
| lab-kiosk-01 | Facilities | lobby kiosk (isolated VLAN) | no | no agent (not required) |

**Protocol.** A2A JSON-RPC at the root URL, agent card at
`/.well-known/agent-card.json` (skills `lookup_hosts`, `list_inventory`). The message
text is JSON — `{"op": "lookup", "hosts": ["lab-db-01"]}` or `{"op": "list"}` — or plain
text naming hosts ("who owns lab-db-01?"). The reply is JSON:
`{ok, op, source, updated, hosts: [{host, owner, contact, role, criticality,
should_be_monitored}], not_found}`.

**Caller.** `wazuh_agent` uses ADK's `RemoteA2aAgent` (`use_legacy=False`) driven by
its own `Runner` from code nodes (`agent/wazuh_agent/assets.py`): 8 s timeout, reply
validated with Pydantic, every failure → "inventory unavailable" while the Wazuh part
still answers. Both sides log one line per request and one per response:

```
A2A ▶ wazuh_agent → asset_agent (http://127.0.0.1:8030) | question: {"op": "lookup", "hosts": ["lab-db-01"]}
A2A ◀ asset_agent → wazuh_agent | answer: lab-db-01: owner=Database team, role=PostgreSQL primary | 17 ms
```

Read-only: the server has no operation that changes the inventory; binds to 127.0.0.1.
