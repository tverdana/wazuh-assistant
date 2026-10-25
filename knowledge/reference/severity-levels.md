---
type: Reference
title: Wazuh rule levels
description: Official meaning of rule levels 0-16 and the assistant's severity labels.
tags: [reference, severity, levels, rules, classification]
sources:
  - id: rules-classification
    resource: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
    title: "Wazuh docs: rules classification"
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Official levels

| Level | Title |
|---|---|
| 0 | Ignored |
| 1 | Low relevance information |
| 2 | System low priority notification |
| 3 | Successful/Authorized events |
| 4 | System low priority error |
| 5 | User generated error |
| 6 | Low relevance attack |
| 7 | "Bad word" matching |
| 8 | First time seen |
| 9 | Error from invalid source |
| 10 | Multiple user generated errors |
| 11 | Integrity checking warning |
| 12 | High importance event |
| 13 | Unusual error (high importance) |
| 14 | High importance security event |
| 15 | Severe attack |
| 16 | Maximum severity (reserved for custom rules) |

Source: Wazuh rules classification.[^rules-classification]

# Severity labels used by this assistant

The official page defines no groups. The assistant labels levels as **low** 0–6,
**medium** 7–11, **high** 12–14 and **critical** 15–16 (its own convention). The lab's
SSH brute-force rules (level 10) are therefore "medium", and "high severity" in a
question maps to `min_level=12`.

[^rules-classification]: Wazuh docs: rules classification
