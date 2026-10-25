"""Code metric `source_cited` (0/1, see eval_config.yaml).

Knowledge answers must cite the concept file they come from, and every cited
`knowledge/...md` path must exist in the repo (no invented citations). For
`knowledge_not_found` the reply must say nothing was found instead of citing a
concept. Cases without a citation expectation are not applicable and score 1.
"""

import re
from pathlib import Path


def _repo_root() -> Path:
    # agents-cli execs this file without __file__: find the repo from the cwd
    for base in [Path.cwd(), *Path.cwd().parents]:
        if (base / "knowledge" / "index.md").is_file():
            return base
    return Path.cwd()


REPO = _repo_root()
_CITED = re.compile(r"knowledge/[\w./-]+\.md")

EXPECTED = {
    "knowledge_ssh_runbook": ["knowledge/runbooks/ssh-bruteforce.md"],
    "knowledge_agent_disconnected": ["knowledge/runbooks/agent-disconnected.md"],
    "knowledge_fim_authorized_keys": ["knowledge/runbooks/fim-change.md"],
    "knowledge_adr_read_only": ["knowledge/decisions/adr-0001-read-only-assistant.md"],
    "knowledge_how_to_block_ip": ["knowledge/runbooks/ssh-bruteforce.md"],
    "knowledge_list_runbooks": [
        "knowledge/runbooks/agent-disconnected.md",
        "knowledge/runbooks/ssh-bruteforce.md",
        "knowledge/runbooks/fim-change.md",
        "knowledge/runbooks/unauthorized-sudo.md",
        "knowledge/runbooks/prompt-injection-in-logs.md",
    ],
    # explain_rule points to the runbook that lists the rule
    "normal_explain_rule": ["knowledge/runbooks/ssh-bruteforce.md"],
}


def _response_text(instance) -> str:
    response = instance.get("response") or {}
    if isinstance(response, str):
        return response
    return "".join(
        p.get("text", "") for p in response.get("parts") or [] if isinstance(p, dict)
    )


def evaluate(instance):
    text = _response_text(instance)
    case_id = str(instance.get("eval_case_id", ""))
    cited = set(_CITED.findall(text))
    missing_files = sorted(p for p in cited if not (REPO / p).is_file())
    if missing_files:
        return {
            "score": 0,
            "explanation": f"cites files that do not exist: {missing_files}",
        }
    if case_id == "knowledge_not_found":
        if "found no concept" in text and "Source: `" not in text:
            return {
                "score": 1,
                "explanation": "reported not found, no concept presented",
            }
        return {"score": 0, "explanation": "presented a concept for an unknown topic"}
    expected = EXPECTED.get(case_id)
    if expected is None:
        return {"score": 1, "explanation": "no citation expected (n/a)"}
    missing = [p for p in expected if p not in cited]
    if missing:
        return {"score": 0, "explanation": f"missing citation(s): {missing}"}
    return {"score": 1, "explanation": f"cites {', '.join(expected)}"}
