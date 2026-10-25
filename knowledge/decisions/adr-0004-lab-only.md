---
type: Architecture Decision Record
title: "ADR-0004: Local lab only"
description: Host allowlist, loopback-only ports and pinned TLS; the assistant never talks to a production Wazuh.
tags: [adr, security, lab, tls, network]
adr_status: accepted
sources:
  - id: settings-py
    resource: ../../wazuh_mcp/wazuh_mcp/settings.py
    title: wazuh_mcp settings (host allowlist)
  - id: lab-override
    resource: ../../lab/compose.lab-override.yml
    title: Lab port bindings (127.0.0.1 only)
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Status

Accepted (2026-10-25).

# Context

The project is coursework. Pointing it at a real SIEM would expose production
data to an LLM provider and to an experimental tool.

# Decision

- The lab runs the official wazuh-docker single-node v4.14.9 with every port bound
  to 127.0.0.1; agents enroll over the internal compose network.[^lab-override]
- `wazuh_mcp` refuses to start unless the API and indexer URLs point to an
  allowlisted lab host (`127.0.0.1`, `localhost`, `wazuh.manager`, `wazuh.indexer`).[^settings-py]
- TLS is verified: the indexer certificate against the lab CA and the name
  `wazuh.indexer`; the API's self-signed certificate is pinned.
- Secrets live only in gitignored files (`lab/admin.env`, `lab/readonly.env`, `.env`).

# Consequences

- Using another lab requires an explicit `WAZUH_ALLOWED_HOSTS`, never a default.
- See [Lab environment](/reference/lab-environment.md).

[^settings-py]: wazuh_mcp settings
[^lab-override]: Lab port bindings
