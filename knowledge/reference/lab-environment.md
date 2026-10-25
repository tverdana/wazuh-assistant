---
type: Reference
title: Lab environment
description: Containers, agents, ports, identities and alert scenarios of the local lab.
tags: [reference, lab, agents, ports, docker]
resource: ../../lab/compose.yaml
sources:
  - id: lab-readme
    resource: ../../lab/README.md
    title: Lab README
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Components

| Component | Details |
|---|---|
| Wazuh manager | `wazuh-lab-wazuh.manager-1`, API on `127.0.0.1:55000` |
| Wazuh indexer | `wazuh-lab-wazuh.indexer-1`, `127.0.0.1:9200`, alerts in `wazuh-alerts-*` |
| Wazuh dashboard | `https://localhost` (`127.0.0.1:443`) |
| Agent 001 `lab-web-01` | active; fake auth log `/var/log/lab/auth.log`, realtime FIM on `/lab/fim`, rootcheck every 5 min |
| Agent 002 `lab-db-01` | enrolled, then stopped on purpose → disconnected ([runbook](/runbooks/agent-disconnected.md)) |
| `wazuh_mcp` | read-only MCP server, `http://127.0.0.1:8020/mcp` |
| `wazuh_agent` playground | `http://127.0.0.1:8502` |

Read-only identities: API `assistant_api_ro`, indexer `assistant_idx_ro`
([ADR-0001](/decisions/adr-0001-read-only-assistant.md)). Passwords are only in
gitignored `lab/readonly.env`.

# Alert scenarios (`lab/lab.sh alerts <scenario>`)

| Scenario | Alerts |
|---|---|
| `ssh` | 5710/5760 failures from 203.0.113.45 → 5712/5763 brute force, 5715 success ([runbook](/runbooks/ssh-bruteforce.md)) |
| `sudo` | 5405 unauthorized sudo by `mallory`, 5403/5402 normal sudo ([runbook](/runbooks/unauthorized-sudo.md)) |
| `fim` | 550/554/553 on `/lab/fim` incl. `authorized_keys` ([runbook](/runbooks/fim-change.md)) |
| `injection` | prompt-injection text inside 5405 and 5710 alerts ([runbook](/runbooks/prompt-injection-in-logs.md)) |

Always present: SCA (CIS Amazon Linux 2023, 19003/19007–19009) and rootcheck 510
for the planted hidden file `/dev/.lab-hidden-bait`.
