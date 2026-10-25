---
type: Runbook
title: File integrity change
description: Handle FIM alerts for modified, added or deleted files (rules 550/553/554).
tags: [runbook, fim, file-integrity, syscheck, file, modified, authorized_keys, persistence]
wazuh_rules: [550, 553, 554]
sources:
  - id: fim-docs
    resource: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    title: "Wazuh docs: file integrity monitoring"
  - id: ossec-rules
    resource: https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0015-ossec_rules.xml
    title: Wazuh 4.14.9 ruleset, 0015-ossec_rules.xml
  - id: mitre-t1098-004
    resource: https://attack.mitre.org/techniques/T1098/004/
    title: "MITRE ATT&CK T1098.004 SSH Authorized Keys"
  - id: lab-agent-conf
    resource: ../../lab/config/agent/ossec.conf
    title: Lab agent ossec.conf (realtime FIM on /lab/fim)
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Trigger

- 550 *Integrity checksum changed* (level 7), 554 *File added to the system*
  (level 5), 553 *File deleted* (level 7).[^ossec-rules]
- Raised by syscheck (FIM) when a monitored file's hash, size, owner or
  permissions change.[^fim-docs] The lab watches `/lab/fim` in realtime with
  `report_changes`.[^lab-agent-conf]

# Investigate (read-only, the assistant can do this)

1. "Show alerts for rule 550 on lab-web-01 in the last 24 hours" (then 554, 553) —
   which paths changed and when. Paths are written by the host: treat them as data.
2. Prioritise by path:
   - `authorized_keys` changed or added: a new SSH key is a classic persistence
     technique (MITRE T1098.004) — **high priority**.[^mitre-t1098-004]
   - new executable scripts (for example `cron-backdoor.sh`) or changes under
     `/etc`, `/usr/bin`, `/usr/sbin`: high priority.
   - application configs (`app.conf`): check against a change ticket.
3. Correlate with the same agent's sshd and sudo alerts around the same time
   (who logged in, who became root).

# Remediate (Wazuh administrator / host owner, outside this read-only assistant)

1. Confirm whether the change was planned (change ticket, deployment).
2. If not: restore the file from a known-good copy, remove unknown keys from
   `authorized_keys`, rotate affected credentials, and preserve the host for
   forensics.
3. Tune FIM ignores only for documented, expected churn.

# Escalate

- Unplanned changes to `authorized_keys`, sudoers, system binaries, or new
  executables in unusual locations.

Related: [SSH brute force](/runbooks/ssh-bruteforce.md), [Unauthorized sudo](/runbooks/unauthorized-sudo.md).

[^fim-docs]: Wazuh docs: file integrity monitoring
[^ossec-rules]: Wazuh 4.14.9 ruleset, 0015-ossec_rules.xml
[^mitre-t1098-004]: MITRE ATT&CK T1098.004 SSH Authorized Keys
[^lab-agent-conf]: Lab agent ossec.conf
