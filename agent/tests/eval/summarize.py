"""Print the latest eval results as Markdown tables (per case and per category).

uv run python tests/eval/summarize.py artifacts/grade_results/normal artifacts/grade_results/guardrails
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

METRICS = [
    "custom_response_quality",
    "refusal_or_action",
    "tool_routing",
    "untrusted_data_safe",
    "agent_turn_count",
]
SHORT = [
    "quality (1-5)",
    "refusal_or_action",
    "tool_routing",
    "untrusted_safe",
    "turns",
]
CATEGORIES = [
    ("normal_", "normal"),
    ("off_topic_", "off-topic"),
    ("clarify_", "clarify-then-complete"),
    ("write_", "write-request refusal"),
    ("injection_", "prompt injection"),
]


def _latest(directory: Path) -> Path:
    return max(directory.glob("results_*.json"))


def _rows(path: Path):
    data = json.loads(path.read_text())
    datasets = data.get("evaluation_dataset") or []
    if isinstance(datasets, dict):
        datasets = [datasets]
    cases = [c for ds in datasets for c in ds.get("eval_cases") or []]
    for i, result in enumerate(data["eval_case_results"]):
        case_id = (
            cases[i].get("eval_case_id", f"case_{i}") if i < len(cases) else f"case_{i}"
        )
        metrics = result["response_candidate_results"][0]["metric_results"]
        yield case_id, {m: (metrics.get(m) or {}).get("score") for m in METRICS}


def _fmt(value) -> str:
    if value is None:
        return "-"
    return (
        f"{value:.2f}".rstrip("0").rstrip(".")
        if isinstance(value, float)
        else str(value)
    )


def main(dirs: list[str]) -> None:
    rows = []
    for d in dirs:
        path = _latest(Path(d))
        print(f"<!-- {path} -->")
        rows += list(_rows(path))

    print("| case | " + " | ".join(SHORT) + " |")
    print("|---|" + "---|" * len(SHORT))
    for case_id, scores in rows:
        print(f"| {case_id} | " + " | ".join(_fmt(scores[m]) for m in METRICS) + " |")

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for case_id, scores in rows:
        cat = next(
            (name for prefix, name in CATEGORIES if case_id.startswith(prefix)), "other"
        )
        by_cat[cat].append(scores)
    print()
    print("| category | cases | " + " | ".join(SHORT[:-1]) + " |")
    print("|---|---|" + "---|" * (len(SHORT) - 1))
    for _, cat in [*CATEGORIES, ("", "other")]:
        group = by_cat.get(cat)
        if not group:
            continue
        means = []
        for m in METRICS[:-1]:
            vals = [s[m] for s in group if s[m] is not None]
            means.append(_fmt(sum(vals) / len(vals)) if vals else "-")
        print(f"| {cat} | {len(group)} | " + " | ".join(means) + " |")
    all_means = []
    for m in METRICS[:-1]:
        vals = [s[m] for _, s in rows if s[m] is not None]
        all_means.append(_fmt(sum(vals) / len(vals)) if vals else "-")
    print(f"| **all** | {len(rows)} | " + " | ".join(all_means) + " |")


if __name__ == "__main__":
    main(
        sys.argv[1:]
        or ["artifacts/grade_results/normal", "artifacts/grade_results/guardrails"]
    )
