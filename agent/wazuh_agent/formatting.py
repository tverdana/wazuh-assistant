"""Deterministic rendering of wazuh_mcp tool results (no LLM involved).

Text written by monitored hosts (log lines, usernames, commands, file paths) is
attacker-controllable. It is rendered as inert inline code — no Markdown, links
or HTML can come out of it — and alerts flagged `injection_suspected` by the MCP
server get an explicit warning. Nothing in an alert is ever acted upon.
"""

import posixpath
import re
from typing import Any

from wazuh_agent.assets import ASSET_AGENT_URL

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


# ---------------------------------------------------------------------------
# Asset inventory (asset_agent over A2A): another system's data, escaped
# ---------------------------------------------------------------------------


def _assets_by_host(inventory: dict | None) -> dict[str, dict]:
    return {h["host"].lower(): h for h in (inventory or {}).get("hosts", [])}


def _inventory_source(inventory: dict) -> str:
    updated = (
        f", updated {md(inventory['updated'])}" if inventory.get("updated") else ""
    )
    return f"_Owner/role from asset\\_agent via A2A ({md(inventory.get('source') or 'inventory')}{updated})._"


def _inventory_unavailable(what: str) -> str:
    return (
        f"_{what}: the asset inventory (asset\\_agent, A2A at {ASSET_AGENT_URL}) "
        "is unavailable._"
    )


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
    inventory = data.get("inventory")
    assets = _assets_by_host(inventory)
    extra = " Owner | Role |" if inventory else ""
    rows = [
        f"| ID | Name | Status | IP | OS | Version | Last keepalive |{extra}",
        "|---|---|---|---|---|---|---|" + ("---|---|" if inventory else ""),
    ]
    for a in agents:
        row = (
            f"| {md(a.get('id'))} | {md(a.get('name'))} | {md(a.get('status'))} | "
            f"{md(a.get('ip') or '')} | {md(a.get('os') or '')} | "
            f"{md(a.get('agent_version') or '')} | {_time(a.get('last_keepalive'))} |"
        )
        if inventory:
            asset = assets.get(str(a.get("name", "")).lower())
            row += (
                f" {md(asset.get('owner'))} | {md(asset.get('role'))} |"
                if asset
                else " _not in inventory_ | |"
            )
        rows.append(row)
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
    if "inventory" in data:
        lines += [
            "",
            _inventory_source(inventory)
            if inventory
            else _inventory_unavailable("Owner/role not shown"),
        ]
    return "\n".join(lines)


def _agent_status(agent: dict | None) -> str:
    if not agent:
        return "no Wazuh agent"
    return f"agent {md(agent.get('id'))} {md(agent.get('status'))}"


def format_host_info(data: dict, args: dict) -> str:
    host = md(data.get("host"))
    agent = data.get("agent")
    inventory = data.get("inventory")
    asset = _assets_by_host(inventory).get(str(data.get("host", "")).lower())
    lines = []
    if inventory and asset:
        contact = f" ({md(asset.get('contact'))})" if asset.get("contact") else ""
        monitored = "yes" if asset.get("should_be_monitored") else "no"
        lines.append(
            f"**{host}** — owner **{md(asset.get('owner'))}**{contact}, role: "
            f"{md(asset.get('role'))}, criticality: {md(asset.get('criticality'))}, "
            f"should be monitored: {monitored}."
        )
    elif inventory:
        lines.append(f"**{host}** is not in the asset inventory.")
    else:
        lines += [f"**{host}**", "", _inventory_unavailable("Owner and role unknown")]
    lines.append("")
    if data.get("wazuh_error"):
        lines.append(f"Wazuh: status unavailable ({md(data['wazuh_error'], 200)}).")
    elif agent:
        lines.append(
            f"Wazuh: agent {md(agent.get('id'))}, **{md(agent.get('status'))}**, last keepalive "
            f"{_time(agent.get('last_keepalive'))}, {md(agent.get('os') or '')}, "
            f"{md(agent.get('agent_version') or '')}."
        )
    else:
        lines.append(f"Wazuh: no agent named {host}.")
    if asset and asset.get("should_be_monitored") and not data.get("wazuh_error"):
        if not agent:
            lines += [
                "",
                "⚠️ Coverage gap: should be monitored but has no Wazuh agent — an administrator must enroll one.",
            ]
        elif agent.get("status") != "active":
            lines += [
                "",
                f"⚠️ Coverage gap: should be monitored but the agent is {md(agent.get('status'))} "
                "— see `knowledge/runbooks/agent-disconnected.md`.",
            ]
    if inventory:
        lines += ["", _inventory_source(inventory)]
    return "\n".join(lines)


def coverage_rows(agents: list[dict], inventory: dict) -> tuple[list[dict], list[dict]]:
    """Inventory hosts joined with Wazuh agents by name, plus agents unknown to it."""
    by_name = {str(a.get("name", "")).lower(): a for a in agents}
    rows = []
    for asset in inventory.get("hosts", []):
        agent = by_name.get(asset["host"].lower())
        if not asset.get("should_be_monitored"):
            gap = "not required"
        elif agent is None:
            gap = "missing"
        elif agent.get("status") != "active":
            gap = agent.get("status", "unknown")
        else:
            gap = "ok"
        rows.append({"asset": asset, "agent": agent, "gap": gap})
    known = {h["host"].lower() for h in inventory.get("hosts", [])}
    unknown = [a for name, a in by_name.items() if name not in known]
    return rows, unknown


_GAP_LABELS = {
    "ok": "✅ ok",
    "missing": "❌ missing from Wazuh",
    "not required": "not required",
}


def format_coverage(data: dict, args: dict) -> str:
    inventory = data.get("inventory")
    agents = data.get("agents", [])
    if not inventory:
        seen = (
            ", ".join(f"{md(a.get('name'))} ({md(a.get('status'))})" for a in agents)
            or "none"
        )
        return "\n".join(
            [
                "**Monitoring coverage** — cannot be computed.",
                "",
                _inventory_unavailable(
                    "Inventory hosts missing from Wazuh are unknown"
                ),
                "",
                f"What Wazuh itself shows: {len(agents)} agent(s) — {seen}.",
            ]
        )
    rows, unknown = coverage_rows(agents, inventory)
    required = [r for r in rows if r["gap"] != "not required"]
    ok = sum(r["gap"] == "ok" for r in required)
    missing = [r for r in required if r["gap"] == "missing"]
    down = [r for r in required if r["gap"] not in ("ok", "missing")]
    lines = [
        "**Monitoring coverage** — asset inventory (asset\\_agent via A2A) vs Wazuh agents",
        "",
        f"{len(required)} hosts should be monitored: {ok} ok, {len(down)} with a "
        f"disconnected/inactive agent, {len(missing)} missing from Wazuh · "
        f"{len(rows) - len(required)} host(s) do not need monitoring.",
        "",
        "| Host | Owner | Role | Should be monitored | Wazuh | Coverage |",
        "|---|---|---|---|---|---|",
    ]
    if data.get("wazuh_error"):
        lines[2] = (
            f"Wazuh agent list unavailable ({md(data['wazuh_error'], 200)}); every host shows as missing."
        )
    for r in rows:
        a = r["asset"]
        gap = _GAP_LABELS.get(r["gap"], f"⚠️ agent {md(r['gap'])}")
        lines.append(
            f"| {md(a['host'])} | {md(a.get('owner'))} | {md(a.get('role'), 60)} | "
            f"{'yes' if a.get('should_be_monitored') else 'no'} | {_agent_status(r['agent'])} | {gap} |"
        )
    gaps = missing + down
    if gaps:
        lines += ["", "**Gaps**"]
        for r in missing:
            a = r["asset"]
            lines.append(
                f"- {md(a['host'])} (owner {md(a.get('owner'))}, {md(a.get('contact'))}): "
                "no Wazuh agent — an administrator must enroll one."
            )
        for r in down:
            a = r["asset"]
            lines.append(
                f"- {md(a['host'])} (owner {md(a.get('owner'))}, {md(a.get('contact'))}): "
                f"agent {md(r['gap'])} — see `knowledge/runbooks/agent-disconnected.md`."
            )
    if unknown:
        names = ", ".join(md(a.get("name")) for a in unknown)
        lines += ["", f"Wazuh agents not in the inventory: {names}."]
    lines += ["", _inventory_source(inventory)]
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
    if data.get("rule_id"):
        filters.append(f"rule {md(data['rule_id'])}")
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
    for hit in data.get("related_knowledge") or []:
        lines.append(
            f"- **{md(hit.get('type'))}:** {md(hit.get('title'))} — `{hit.get('path')}`"
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


# ---------------------------------------------------------------------------
# Knowledge bundle (trusted markdown reviewed in git; always cite the file)
# ---------------------------------------------------------------------------

_MD_LINK = re.compile(r"\[([^\]]+)\]\((/?[^)\s]+\.md)\)")
_FOOTNOTE_DEF = re.compile(r"^\[\^[\w-]+\]:.*$\n?", re.MULTILINE)
_HEADING = re.compile(r"^(#{1,4}) ", re.MULTILINE)
READ_ONLY_NOTE = (
    "**Note:** remediation steps are for a Wazuh administrator — this assistant is "
    "read-only and does not run them."
)


def _bundle_path(target: str, doc_path: str) -> str:
    """'/runbooks/x.md' or './x.md' inside knowledge/... -> repo-relative path."""
    bundle = doc_path.split("/", 1)[0]  # "knowledge"
    if target.startswith("/"):
        return f"{bundle}{target}"
    return posixpath.normpath(posixpath.join(posixpath.dirname(doc_path), target))


def _source_label(resource: str, doc_path: str) -> str:
    if resource.startswith(("http://", "https://")) or " " in resource:
        return resource  # URL or a scope description
    return _bundle_path(
        resource, doc_path
    )  # e.g. ../../lab/compose.yaml -> lab/compose.yaml


def _knowledge_body(doc: dict) -> str:
    path = doc.get("path", "")
    body = _FOOTNOTE_DEF.sub("", doc.get("body", ""))
    for n, src in enumerate(doc.get("sources") or [], 1):
        if src.get("id"):
            body = body.replace(f"[^{src['id']}]", f" [{n}]")
    body = _MD_LINK.sub(
        lambda m: f"{m.group(1)} (`{_bundle_path(m.group(2), path)}`)", body
    )
    body = _HEADING.sub(lambda m: "#" * min(len(m.group(1)) + 2, 6) + " ", body)
    return body.strip()


def _catalog(listing: dict | None) -> list[str]:
    rows = ["| Type | Title | File | Description |", "|---|---|---|---|"]
    rows += [
        f"| {md(h.get('type'))} | {md(h.get('title'))} | `{h.get('path')}` | "
        f"{md(h.get('description') or '', 110)} |"
        for h in (listing or {}).get("hits", [])
    ]
    return rows


def format_knowledge(data: dict, args: dict) -> str:
    mode = data.get("mode")
    listing = data.get("listing") or {}
    bundle = listing.get("bundle", "knowledge/")
    if mode == "list":
        kind = listing.get("type_filter") or "concepts"
        head = (
            f"📘 **Knowledge bundle** `{bundle}` (OKF {listing.get('okf_version') or '?'})"
            f" — {listing.get('total', 0)} {md(kind)}:"
        )
        return "\n".join([head, "", *_catalog(listing)])
    if mode == "not_found":
        head = (
            f"I found no concept about “{md(data.get('query'))}” in the knowledge "
            f"bundle `{bundle}`, so I won't guess. What it contains:"
        )
        return "\n".join([head, "", *_catalog(listing)])

    doc = data.get("doc") or {}
    updated = (doc.get("generated_at") or "")[:10]
    lines = [
        f"📘 **{md(doc.get('title'))}** — {md(doc.get('type'))} from the knowledge bundle",
        f"Source: `{doc.get('path')}` · OKF concept `{doc.get('id')}` · trust: "
        f"{md(doc.get('trust'))}" + (f" · updated {updated}" if updated else ""),
    ]
    if doc.get("description"):
        lines += ["", f"> {md(doc['description'], 300)}"]
    lines += ["", _knowledge_body(doc)]
    sources = doc.get("sources") or []
    if sources:
        lines += ["", "**Sources**", ""]
        lines += [
            f"{i}. {md(src.get('title') or '')} — "
            f"{_source_label(src.get('resource', ''), doc.get('path', ''))}"
            for i, src in enumerate(sources, 1)
        ]
    if str(doc.get("type", "")).lower() == "runbook":
        lines += ["", READ_ONLY_NOTE]
    also = data.get("also") or []
    if also:
        others = ", ".join(f"{md(h.get('title'))} (`{h.get('path')}`)" for h in also)
        lines += ["", f"Other matches: {others}"]
    return "\n".join(lines)


FORMATTERS = {
    "list_agents": format_agents,
    "list_alerts": format_alerts,
    "alert_stats": format_stats,
    "explain_rule": format_rule,
    "sca_summary": format_sca,
    "knowledge": format_knowledge,
    "host_info": format_host_info,
    "coverage_gap": format_coverage,
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
