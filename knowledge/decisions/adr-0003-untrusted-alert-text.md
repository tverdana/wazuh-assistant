---
type: Architecture Decision Record
title: "ADR-0003: Alert text is untrusted data"
description: Log content never reaches the LLM, is rendered as inert quoted data and injection-looking alerts are flagged.
tags: [adr, security, prompt-injection, untrusted-data, logs]
adr_status: accepted
sources:
  - id: owasp-llm
    resource: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    title: OWASP Top 10 for LLM Applications (LLM01 Prompt Injection)
  - id: untrusted-py
    resource: ../../wazuh_mcp/wazuh_mcp/untrusted.py
    title: wazuh_mcp untrusted-text handling
  - id: formatting-py
    resource: ../../agent/wazuh_agent/formatting.py
    title: wazuh_agent deterministic formatting
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Status

Accepted (2026-10-25).

# Context

Alert fields such as `full_log`, `srcuser`, `command` and FIM paths are written by
monitored hosts, so an attacker controls them. Feeding them to an LLM enables
indirect prompt injection.[^owasp-llm]

# Decision

1. **MCP server** strips ANSI, control, zero-width and bidi characters, caps
   lengths and sets `injection_suspected` on alerts whose text looks like
   instructions to an AI.[^untrusted-py]
2. **The classifier never reads tool output.** Its input is the user's message,
   the user's earlier messages and code-written turn summaries
   (`ran list_alerts(agent=lab-web-01)`), never assistant replies.
3. **Replies are rendered in code**: host-written text becomes inert inline code
   (no Markdown, links or HTML), flagged alerts get an explicit warning.[^formatting-py]
4. Read-only by design ([ADR-0001](/decisions/adr-0001-read-only-assistant.md)) bounds
   the blast radius of anything that slips through.

# Consequences

- Eval cases `injection_*` check that injected text is quoted, warned about and
  never followed; see [Prompt injection in logs](/runbooks/prompt-injection-in-logs.md).
- The assistant cannot "summarise" log lines with an LLM; that is accepted.

[^owasp-llm]: OWASP Top 10 for LLM Applications
[^untrusted-py]: wazuh_mcp untrusted-text handling
[^formatting-py]: wazuh_agent deterministic formatting
