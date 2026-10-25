# Architecture Decision Records

* [ADR-0001 Read-only by design](adr-0001-read-only-assistant.md) - The assistant can never change Wazuh; enforced in three layers.
* [ADR-0002 One LLM node, routing in code](adr-0002-single-llm-node.md) - Graph workflow where only intent classification uses the LLM.
* [ADR-0003 Alert text is untrusted data](adr-0003-untrusted-alert-text.md) - Log content never reaches the LLM and is rendered inert.
* [ADR-0004 Local lab only](adr-0004-lab-only.md) - Host allowlist, loopback ports and pinned TLS; never a production Wazuh.
* [ADR-0005 Knowledge as an OKF bundle](adr-0005-okf-knowledge-bundle.md) - Runbooks and ADRs as OKF markdown served by read-only MCP tools.
