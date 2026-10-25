---
type: Runbook
title: Agent disconnected
description: Triage a Wazuh agent whose status is disconnected (rules 504/506).
tags: [runbook, agent, disconnected, keepalive, connectivity, offline, down]
wazuh_rules: [504, 506]
sources:
  - id: agent-connection
    resource: https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html
    title: "Wazuh docs: checking the agent connection"
  - id: global-conf
    resource: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html
    title: "Wazuh docs: ossec.conf <global> (agents_disconnection_time)"
  - id: ossec-rules
    resource: https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0015-ossec_rules.xml
    title: Wazuh 4.14.9 ruleset, 0015-ossec_rules.xml
  - id: lab-compose
    resource: ../../lab/compose.yaml
    title: Lab compose file (lab-db-01 is stopped on purpose by lab.sh up)
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Trigger

- `list_agents` reports an agent with status `disconnected`. The manager marks an
  agent disconnected when it gets no keepalive for longer than
  `agents_disconnection_time` (10m in this lab).[^global-conf]
- Related alerts: rule 504 *Wazuh agent disconnected* and rule 506 *Wazuh agent
  stopped* (level 3, MITRE T1562.001 Disable or Modify Tools).[^ossec-rules]
  A 506 means the agent service was stopped cleanly; no 506 before the silence
  points to a host, network or crash problem.

In the lab, `lab-db-01` (agent 002) is disconnected by design.[^lab-compose]

# Investigate (read-only, the assistant can do this)

1. "Which agents are disconnected?" — note the last keepalive, IP and agent version.
2. "Show alerts on lab-db-01 in the last 24 hours" — look for rule 506 (stopped)
   and for the last events the agent sent before it went silent.
3. "Explain rule 506" — confirm what the stop event means.
4. Check whether the host is supposed to be monitored at all (owner / role in the
   asset inventory) before escalating.
5. "SCA summary for lab-db-01" still works: results come from the last completed scan.

# Remediate (Wazuh administrator, outside this read-only assistant)

1. On the host, check the agent service (`systemctl status wazuh-agent`; in the lab
   `docker ps -a --filter name=lab-db-01`).
2. Check connectivity from the host to the manager on 1514/tcp (events) and
   1515/tcp (enrollment).[^agent-connection]
3. Read the agent log `/var/ossec/logs/ossec.log` for connection or key errors.
4. Start/restart the agent (`systemctl restart wazuh-agent`; lab: `docker start lab-db-01`)
   and confirm the status returns to `active`.

# Escalate

- Silent for more than 1 hour without a planned change, or a 504 without a
  preceding 506: treat the host as possibly tampered (an attacker disabling the
  agent is MITRE T1562.001) and contact the host owner.

Related: [Lab environment](/reference/lab-environment.md).

[^agent-connection]: Wazuh docs: checking the agent connection
[^global-conf]: Wazuh docs: ossec.conf global section
[^ossec-rules]: Wazuh 4.14.9 ruleset, 0015-ossec_rules.xml
[^lab-compose]: Lab compose file
