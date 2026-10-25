---
type: Architecture Decision Record
title: "ADR-0001: Read-only by design"
description: The assistant can never change Wazuh; enforced in three independent layers.
tags: [adr, security, read-only, rbac, least-privilege, write-request]
adr_status: accepted
sources:
  - id: rbac
    resource: https://documentation.wazuh.com/current/user-manual/api/rbac/index.html
    title: "Wazuh docs: API RBAC"
  - id: bootstrap
    resource: ../../lab/scripts/bootstrap_readonly.py
    title: Read-only identity bootstrap script
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Status

Accepted (2026-10-25).

# Context

A SIEM assistant that can delete agents, restart services, run active responses
or edit rules is a high-value target: an LLM can be talked into a wrong action by
a user mistake or by text planted in logs ([ADR-0003](/decisions/adr-0003-untrusted-alert-text.md)).
The homework scope only needs investigation.

# Decision

The assistant is strictly read-only, enforced three times:

1. **Identities** — the Wazuh API user `assistant_api_ro` has a custom role with
   `*:read` policies only and `allow_run_as=false`; the indexer user
   `assistant_idx_ro` has the `read` action group on `wazuh-alerts-*` only.[^rbac][^bootstrap]
   Writes are verified to return HTTP 403 (`lab/lab.sh verify`).
2. **MCP server** — HTTP clients without write methods (API: GET on an allowlist of
   paths; indexer: `_search` only) and no tool that changes anything; every tool
   carries `readOnlyHint=true`.
3. **Agent** — `route_intent` refuses write requests (delete, restart, change,
   block, run…) in code before any tool runs, whatever the LLM classified.

# Consequences

- Remediation steps in [runbooks](/runbooks/index.md) are for a human administrator.
- A misclassification or a successful prompt injection can at worst trigger an
  extra read.
- Adding a write capability later needs a new ADR, a human approval step and
  separate credentials.

[^rbac]: Wazuh docs: API RBAC
[^bootstrap]: Read-only identity bootstrap script
