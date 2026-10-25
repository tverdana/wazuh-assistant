---
type: Architecture Decision Record
title: "ADR-0002: One LLM node, routing in code"
description: Graph workflow where only intent classification uses the LLM; routing, tool calls and replies are code.
tags: [adr, architecture, adk, graph-workflow, routing, llm]
adr_status: accepted
sources:
  - id: agent-code
    resource: ../../agent/wazuh_agent/agent.py
    title: wazuh_agent graph (agent.py)
  - id: ezstore
    resource: "ezstore repository (first homework): agent/quotation_agent/agent.py"
    title: First homework agent (ezstore quotation_agent), same pattern
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Status

Accepted (2026-10-25).

# Context

The first homework agent (ezstore) showed that an ADK 2.x Graph Workflow with a
single classification LLM is predictable, cheap and testable.[^ezstore] A SIEM
assistant additionally must not let tool output steer its behaviour.

# Decision

`START → prepare_input → classify_intent → route_intent → {tool node | clarify |
refuse | knowledge} → respond`.[^agent-code]

- `classify_intent` is the only LLM call: temperature 0, Pydantic `IntentResult`
  output (intent + parameters), retries 429/503 with exponential backoff.
- `route_intent` (code) applies the guards, validates parameters and asks for
  missing ones; it emits its decision as a thought (`route_intent: ran …`).
- Each tool node calls one read-only MCP tool; `respond` formats in code.

# Consequences

- Behaviour is unit-testable without a model (fake Gemini endpoint).
- Answers are deterministic tables and runbook text, not free-form prose.
- New capabilities are new intents + nodes, not prompt changes.

[^agent-code]: wazuh_agent graph (agent.py)
[^ezstore]: First homework agent (ezstore)
