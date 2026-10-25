"""Deterministic rendering of wazuh_mcp tool results (no LLM involved).

Text written by monitored hosts (log lines, usernames, commands, file paths) is
attacker-controllable. It is rendered as inert inline code — no Markdown, links
or HTML can come out of it — and alerts flagged `injection_suspected` by the MCP
server get an explicit warning. Nothing in an alert is ever acted upon.
"""

import re
from typing import Any

INJECTION_WARNING = (
    "⚠️ **Possible prompt injection in logs.** {n} alert(s) contain text that "
    "looks like instructions to an AI assistant ({where}). This text was written "
    "by the monitored host and is treated as untrusted data: it was **not** "
    "followed and no action was taken. Investigate the source host and user."
)
UNTRUSTED_FOOTER = (
    "_Host-written fields (log lines, users, commands, paths) are shown verbatim "
    "as untrusted data._"
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")


def _plain(value: Any, max_len: int = 200) -> str:
    s = _CONTROL.sub(" ", str(value if value is not None else "")).strip()
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def md(value: Any, max_len: int = 200) -> str:
    """Escape Markdown so semi-trusted text (rule/SCA titles) renders literally."""
    return _MD_SPECIAL.sub(r"\\\1", _plain(value, max_len))


def untrusted(value: Any, max_len: int = 160) -> str:
    """Host-written text as an inert code span (safe inside table cells)."""
    s = _plain(value, max_len).replace("`", "'").replace("|", "¦")
    return f"`{s}`" if s else ""


def _time(ts: str | None) -> str:
    return (ts or "")[:19].replace("T", " ")


def _error_text(tool: str, error: str) -> str:
    return f"I couldn't get that from Wazuh ({tool}): {md(error, 400)}"


# ---------------------------------------------------------------------------
# Per-tool formatters
# ---------------------------------------------------------------------------


def format_agents(data: dict, args: dict) -> str:
    counts = data.get("counts", {})
    status = data.get("status_filter", "all")
    head = (
        f"**Wazuh agents** (filter: {md(status)}) — "
        f"{counts.get('active', 0)} active, {counts.get('disconnected', 0)} disconnected, "
        f"{counts.get('never_connected', 0)} never connected, "
        f"{counts.get('pending', 0)} pending (manager not counted)."
    )
    agents = data.get("agents", [])
    if not agents:
        return head + f"\n\nNo agents with status {md(status)}."
    rows = [
        "| ID | Name | Status | IP | OS | Version | Last keepalive |",
        "|---|---|---|---|---|---|---|",
    ]
    for a in agents:
        rows.append(
            f"| {md(a.get('id'))} | {md(a.get('name'))} | {md(a.get('status'))} | "
            f"{md(a.get('ip') or '')} | {md(a.get('os') or '')} | "
            f"{md(a.get('agent_version') or '')} | {_time(a.get('last_keepalive'))} |"
        )
    lines = [head, "", *rows]
    down = [a for a in agents if a.get("status") == "disconnected"]
    if down:
        names = ", ".join(
            f"{md(a.get('name'))} (last seen {_time(a.get('last_keepalive'))})"
            for a in down
        )
        lines += ["", f"Disconnected: {names}."]
    if data.get("truncated"):
        lines += [
            "",
            f"Showing {data.get('returned')} of {data.get('total_matching')}.",
        ]
    return "\n".join(lines)


def _alert_details(a: dict) -> str:
    parts = []
    if a.get("srcip"):
        parts.append(f"src {untrusted(a['srcip'], 64)}")
    if a.get("srcuser"):
        parts.append(f"user {untrusted(a['srcuser'], 80)}")
    if a.get("dstuser"):
        parts.append(f"as {untrusted(a['dstuser'], 80)}")
    if a.get("command"):
        parts.append(f"cmd {untrusted(a['command'], 120)}")
    if a.get("fim_path"):
        parts.append(
            f"{md(a.get('fim_event') or 'changed')} {untrusted(a['fim_path'], 120)}"
        )
    if not parts and a.get("full_log"):
        parts.append(untrusted(a["full_log"], 120))
    if a.get("injection_suspected"):
        parts.append("⚠️ injection?")
    return " · ".join(parts)


def format_alerts(data: dict, args: dict) -> str:
    filters = [f"last {md(data.get('since', '24h'))}"]
    if data.get("min_level"):
        filters.append(f"level ≥ {data['min_level']}")
    if data.get("agent"):
        filters.append(f"agent {md(data['agent'])}")
    total, returned = data.get("total_matching", 0), data.get("returned", 0)
    head = f"**Alerts** — {', '.join(filters)}: {total} matching"
    alerts = data.get("alerts", [])
    if not alerts:
        return head + ".\n\nNo alerts match these filters."
    head += f", showing the newest {returned}." if data.get("truncated") else "."
    rows = [
        "| Time (UTC) | Agent | Rule | Level | Description | Details |",
        "|---|---|---|---|---|---|",
    ]
    for a in alerts:
        rows.append(
            f"| {_time(a.get('timestamp'))} | {md(a.get('agent_name') or a.get('agent_id'))} | "
            f"{md(a.get('rule_id'))} | {a.get('rule_level', '')} | "
            f"{md(a.get('rule_description'), 90)} | {_alert_details(a)} |"
        )
    lines = [head, "", *rows]
    flagged = [a for a in alerts if a.get("injection_suspected")]
    if flagged:
        where = "; ".join(
            f"rule {md(a.get('rule_id'))} on {md(a.get('agent_name'))} at {_time(a.get('timestamp'))}"
            for a in flagged[:5]
        )
        lines += ["", INJECTION_WARNING.format(n=len(flagged), where=where)]
    lines += ["", UNTRUSTED_FOOTER]
    return "\n".join(lines)


_GROUP_TITLES = {
    "rule": "Rule",
    "agent": "Agent",
    "level": "Level",
    "group": "Group",
    "srcip": "Source IP",
    "mitre": "MITRE technique",
    "tactic": "MITRE tactic",
}


def format_stats(data: dict, args: dict) -> str:
    group = data.get("group_by", "rule")
    head = (
        f"**Alert statistics** — by {md(_GROUP_TITLES.get(group, group).lower())}, "
        f"last {md(data.get('since', '24h'))}: {data.get('total_alerts', 0)} alerts in total."
    )
    buckets = data.get("buckets", [])
    if not buckets:
        return head + "\n\nNo alerts in this window."
    title = _GROUP_TITLES.get(group, md(group))
    key_cell = untrusted if group == "srcip" else md  # source IPs come from logs
    if group == "rule":
        rows = [f"| {title} | Description | Alerts | Max level |", "|---|---|---|---|"]
        rows += [
            f"| {md(b.get('key'))} | {md(b.get('label') or '', 90)} | {b.get('count')} | {b.get('max_level')} |"
            for b in buckets
        ]
    else:
        rows = [f"| {title} | Alerts | Max level |", "|---|---|---|"]
        rows += [
            f"| {key_cell(b.get('key'))} | {b.get('count')} | {b.get('max_level')} |"
            for b in buckets
        ]
    lines = [head, "", *rows]
    if data.get("other_count"):
        lines += ["", f"Other values: {data['other_count']} alerts."]
    return "\n".join(lines)


def format_rule(data: dict, args: dict) -> str:
    lines = [
        f"**Rule {data.get('id')}** — level {data.get('level')} ({md(data.get('severity'))}): "
        f"{md(data.get('description'))}",
        "",
        f"- **What it means:** {md(data.get('summary'), 400)}",
    ]
    if data.get("groups"):
        lines.append(f"- **Groups:** {', '.join(md(g) for g in data['groups'])}")
    conditions = data.get("conditions") or {}
    if conditions:
        cond = ", ".join(
            f"{md(k)}={md(v, 80)}" if v else md(k) for k, v in conditions.items()
        )
        lines.append(f"- **Conditions:** {cond}")
    for t in data.get("mitre") or []:
        tactics = (
            f" ({', '.join(md(x) for x in t.get('tactics', []))})"
            if t.get("tactics")
            else ""
        )
        lines.append(
            f"- **MITRE ATT&CK:** {md(t.get('id'))} {md(t.get('name') or '')}{tactics}"
        )
    compliance = data.get("compliance") or {}
    if compliance:
        names = {
            "pci_dss": "PCI DSS",
            "gdpr": "GDPR",
            "hipaa": "HIPAA",
            "nist_800_53": "NIST 800-53",
            "tsc": "TSC",
        }
        tags = " · ".join(
            f"{names.get(k, md(k))} {', '.join(md(v) for v in vals)}"
            for k, vals in compliance.items()
        )
        lines.append(f"- **Compliance:** {tags}")
    recent = data.get("recent")
    if recent is not None:
        where = ", ".join(
            f"{md(k)}: {v}" for k, v in (recent.get("top_agents") or {}).items()
        )
        lines.append(
            f"- **Last {md(recent.get('since', '24h'))}:** fired {recent.get('count', 0)} times"
            + (f" ({where})" if where else "")
        )
    if data.get("file"):
        lines.append(
            f"- **Defined in:** {md(data['file'])} ({md(data.get('status') or '')})"
        )
    return "\n".join(lines)


def format_sca(data: dict, args: dict) -> str:
    agent = data.get("agent", {})
    head = (
        f"**SCA results for {md(agent.get('name'))}** "
        f"(agent {md(agent.get('id'))}, {md(agent.get('status'))})"
    )
    lines = [head, ""]
    policies = data.get("policies", [])
    if policies:
        lines += [
            "| Policy | Score | Passed | Failed | Not applicable | Last scan |",
            "|---|---|---|---|---|---|",
        ]
        lines += [
            f"| {md(p.get('name'), 80)} | {p.get('score')}% | {p.get('passed')} | "
            f"{p.get('failed')} | {p.get('invalid')} | {_time(p.get('end_scan'))} |"
            for p in policies
        ]
    sample = data.get("failed_checks_sample", [])
    if sample:
        lines += [
            "",
            f"Failed checks ({len(sample)} of {data.get('failed_checks_total', len(sample))}):",
        ]
        lines += [f"- {c.get('id')}: {md(c.get('title'), 160)}" for c in sample]
    if data.get("note"):
        lines += ["", f"Note: {md(data['note'])}."]
    return "\n".join(lines)


FORMATTERS = {
    "list_agents": format_agents,
    "list_alerts": format_alerts,
    "alert_stats": format_stats,
    "explain_rule": format_rule,
    "sca_summary": format_sca,
}


def format_tool_result(
    tool: str | None, args: dict, data: dict | None, error: str | None
) -> str:
    tool = tool or "unknown"
    if error:
        return _error_text(tool, error)
    formatter = FORMATTERS.get(tool)
    if formatter is None or data is None:
        return _error_text(tool, "no formatter for this result")
    return formatter(data, args)
