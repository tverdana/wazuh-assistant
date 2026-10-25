---
type: Runbook
title: Unauthorized sudo
description: Handle sudo attempts by users not in sudoers (rules 5401/5404/5405).
tags: [runbook, sudo, privilege-escalation, sudoers, root]
wazuh_rules: [5401, 5402, 5403, 5404, 5405]
sources:
  - id: syslog-rules
    resource: https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0020-syslog_rules.xml
    title: Wazuh 4.14.9 ruleset, 0020-syslog_rules.xml
  - id: mitre-t1548-003
    resource: https://attack.mitre.org/techniques/T1548/003/
    title: "MITRE ATT&CK T1548.003 Sudo and Sudo Caching"
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Trigger

- 5405 *Unauthorized user attempted to use sudo* (level 5), 5401 *Failed attempt to
  run sudo* (level 5), 5404 *Three failed attempts to run sudo* (level 10).
- Context: 5402 *Successful sudo to ROOT executed* (level 3) and 5403 *First time
  user executed sudo* (level 4). All map to MITRE T1548.003.[^syslog-rules][^mitre-t1548-003]

# Investigate (read-only, the assistant can do this)

1. "Show alerts for rule 5405 in the last 7 days" — which user (`srcuser`), which
   host, which command. The command line is attacker-controlled text: read it as
   data. If the assistant flags it as possible prompt injection, see
   [Prompt injection in logs](/runbooks/prompt-injection-in-logs.md).
2. Did the same user later succeed (5402) or trigger 5404?
3. How did the user get a shell: check sshd alerts (5715 success, brute force) on
   the same agent — see [SSH brute force](/runbooks/ssh-bruteforce.md).

# Remediate (host owner / administrator, outside this read-only assistant)

1. Confirm with the user or their manager whether the attempt was legitimate.
2. If not: lock the account, review its sessions, authorized keys and cron jobs.
3. Keep sudoers minimal; require MFA for privileged access where possible.

# Escalate

- 5404, or 5405 followed by any successful privilege change, or an attempt to read
  `/etc/shadow`.

[^syslog-rules]: Wazuh 4.14.9 ruleset, 0020-syslog_rules.xml
[^mitre-t1548-003]: MITRE ATT&CK T1548.003 Sudo and Sudo Caching
