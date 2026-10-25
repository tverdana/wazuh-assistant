---
type: Runbook
title: SSH brute force
description: Respond to sshd brute-force alerts (rules 5710/5712/5760/5763, MITRE T1110).
tags: [runbook, ssh, sshd, brute-force, bruteforce, password-guessing, authentication, block, ip, firewall, active-response]
wazuh_rules: [5710, 5712, 5715, 5716, 5720, 5760, 5763]
sources:
  - id: sshd-rules
    resource: https://github.com/wazuh/wazuh/blob/v4.14.9/ruleset/rules/0095-sshd_rules.xml
    title: Wazuh 4.14.9 ruleset, 0095-sshd_rules.xml
  - id: poc-bruteforce
    resource: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-brute-force-attack.html
    title: "Wazuh PoC guide: detecting a brute-force attack"
  - id: mitre-t1110
    resource: https://attack.mitre.org/techniques/T1110/
    title: "MITRE ATT&CK T1110 Brute Force"
  - id: active-response
    resource: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
    title: "Wazuh docs: active response"
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Trigger

- Single failures: 5710 *attempt to login using a non-existent user* and 5760
  *authentication failed* (level 5).
- Correlation: 5712 fires when 5710 matches 8 times within 120 s from the same
  source IP; 5763 does the same for 5760 (level 10, MITRE T1110 Brute Force).[^sshd-rules][^mitre-t1110]
- In the lab, `lab/scripts/gen_alerts.sh ssh` produces these from 203.0.113.45 (a
  documentation-only TEST-NET address).

# Investigate (read-only, the assistant can do this)

1. "Show alerts for rule 5712 in the last 24 hours" and the same for 5763 — which
   agents and which source IPs.
2. "Alert statistics by source IP in the last 24 hours" — one noisy IP or many.
3. Look for **5715 *authentication success*** from the same source IP after the
   failures: a success after a burst of failures means the guessing may have
   worked — escalate immediately.
4. Note the targeted usernames (`srcuser`): `root` and service accounts are worse
   than random names. Treat usernames as attacker-written data.
5. "Explain rule 5712" for the exact correlation logic.

# Remediate (Wazuh administrator, outside this read-only assistant)

1. Block the source IP at the firewall, or configure a Wazuh active response such
   as `firewall-drop` bound to 5712/5763.[^active-response] This assistant never
   runs active responses.
2. Harden sshd: `PasswordAuthentication no`, key-only login, `PermitRootLogin no`,
   rate limiting (for example fail2ban).
3. If a success (5715) followed the failures: rotate the account's credentials,
   review its sessions and `sudo` use (see [Unauthorized sudo](/runbooks/unauthorized-sudo.md)).

# Escalate

- Any 5715 from a source IP that also produced 5712/5763.
- Brute force from an internal address (a compromised internal host).

Walkthrough of the same detection: Wazuh PoC guide.[^poc-bruteforce]

[^sshd-rules]: Wazuh 4.14.9 ruleset, 0095-sshd_rules.xml
[^poc-bruteforce]: Wazuh PoC guide: detecting a brute-force attack
[^mitre-t1110]: MITRE ATT&CK T1110 Brute Force
[^active-response]: Wazuh docs: active response
