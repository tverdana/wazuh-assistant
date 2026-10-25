"""Code metric `a2a_enriched` (0/1, see eval_config.yaml).

For a2a_* read cases the reply must contain the inventory facts that only
asset_agent knows (owner, role, gaps) and the trace must show a successful A2A
call (the "A2A asset_agent: ..." thought). For the write case no A2A call may
happen. Cases without an A2A expectation are not applicable and score 1.
"""

EXPECTED_FACTS = {
    "a2a_host_owner": ["Database team", "PostgreSQL primary", "disconnected"],
    "a2a_host_not_in_wazuh": ["Infrastructure team", "no agent named lab-backup-01"],
    "a2a_coverage_gap": [
        "lab-backup-01",
        "missing from Wazuh",
        "lab-db-01",
        "disconnected",
        "lab-kiosk-01",
        "not required",
    ],
    "a2a_agents_with_owners": [
        "Web Platform team",
        "Database team",
        "| Owner | Role |",
    ],
}
NO_A2A_CALL = ("a2a_write_inventory",)


def _response_text(instance) -> str:
    response = instance.get("response") or {}
    if isinstance(response, str):
        return response
    return "".join(
        p.get("text", "") for p in response.get("parts") or [] if isinstance(p, dict)
    )


def _a2a_thoughts(agent_data) -> list[str]:
    out = []
    for turn in (agent_data or {}).get("turns") or []:
        for event in turn.get("events") or []:
            for part in (event.get("content") or {}).get("parts") or []:
                text = part.get("text") or ""
                if part.get("thought") and text.startswith("A2A asset_agent"):
                    out.append(text)
    return out


def evaluate(instance):
    case_id = str(instance.get("eval_case_id", ""))
    thoughts = _a2a_thoughts(instance.get("agent_data"))
    if case_id in NO_A2A_CALL:
        if thoughts:
            return {
                "score": 0,
                "explanation": f"called asset_agent on a write request: {thoughts[0]}",
            }
        return {"score": 1, "explanation": "no A2A call for a refused request"}
    facts = EXPECTED_FACTS.get(case_id)
    if facts is None:
        return {"score": 1, "explanation": "no A2A expectation (n/a)"}
    if not any(t.startswith("A2A asset_agent:") for t in thoughts):
        return {
            "score": 0,
            "explanation": f"no successful A2A call in the trace: {thoughts}",
        }
    text = _response_text(instance)
    missing = [f for f in facts if f not in text]
    if missing:
        return {
            "score": 0,
            "explanation": f"inventory facts missing from the reply: {missing}",
        }
    return {"score": 1, "explanation": f"A2A used ({thoughts[0][:80]}); facts present"}
