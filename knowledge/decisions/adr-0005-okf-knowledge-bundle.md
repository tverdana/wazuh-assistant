---
type: Architecture Decision Record
title: "ADR-0005: Knowledge as an OKF bundle"
description: Runbooks and ADRs are OKF v0.2 markdown, served by read-only MCP tools, and every answer cites its file.
tags: [adr, knowledge, okf, runbooks, citations]
adr_status: accepted
sources:
  - id: okf-spec
    resource: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md
    title: Open Knowledge Format (OKF) specification v0.2
  - id: knowledge-py
    resource: ../../wazuh_mcp/wazuh_mcp/knowledge.py
    title: wazuh_mcp knowledge tools
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
status: stable
---

# Status

Accepted (2026-10-25).

# Context

Analysts need "what do I do now" next to "what happened". The guidance must be
reviewable in git, readable without tooling and attributable.

# Decision

- Knowledge lives in `knowledge/` as an OKF v0.2 bundle: one concept per markdown
  file with YAML frontmatter (`type` required; `title`, `description`, `tags`,
  `sources`, `generated`, `status`), `index.md` per directory, `log.md` history.[^okf-spec]
- The producer-defined key `wazuh_rules` links runbooks to rule ids.
- `wazuh_mcp` serves it with two read-only tools: `list_knowledge` (keyword ranking,
  filters by type or rule id) and `read_knowledge` (one concept by id, path-checked).[^knowledge-py]
- The agent's `knowledge` intent picks the best concept in code and the reply
  always names the source file (`knowledge/runbooks/…md`). `explain_rule` also
  points to runbooks that list the rule.
- Retrieval is keyword-based on purpose: small, deterministic and explainable.

# Consequences

- Bundle text is trusted (it is reviewed in git), unlike alert text.
- Concepts are `unverified` until a human adds `verified: { by: human:<id>, at: … }`.

[^okf-spec]: Open Knowledge Format specification v0.2
[^knowledge-py]: wazuh_mcp knowledge tools
