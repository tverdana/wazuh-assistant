"""Inventory lookups behind the A2A server (pure functions, no LLM).

Request (A2A message text), JSON preferred:
    {"op": "lookup", "hosts": ["lab-db-01"]}     -> records for those hosts
    {"op": "list"}                               -> the whole inventory
Free text also works for manual testing: "who owns lab-db-01?" -> lookup,
anything without a host name -> list.

Reply (A2A message text, JSON):
    {"ok": true, "op": "lookup", "source": ..., "updated": ...,
     "hosts": [{host, owner, contact, role, criticality, should_be_monitored}],
     "not_found": ["unknown-host"]}
"""

import json
import os
import re
from pathlib import Path

DEFAULT_INVENTORY = Path(__file__).resolve().parent / "inventory.json"
MAX_HOSTS = 50
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOST_IN_TEXT_RE = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d{2}\b", re.IGNORECASE)
FIELDS = ("host", "owner", "contact", "role", "criticality", "should_be_monitored")


def load_inventory(path: Path | None = None) -> dict:
    path = path or Path(os.environ.get("ASSET_INVENTORY", DEFAULT_INVENTORY))
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = [{k: h.get(k) for k in FIELDS} for h in data.get("hosts", [])]
    return {
        "source": data.get("source"),
        "updated": data.get("updated"),
        "hosts": hosts,
    }


def parse_request(text: str) -> dict:
    text = (text or "").strip()
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, dict) and obj.get("op") in ("lookup", "list"):
        hosts = [str(h).strip() for h in obj.get("hosts") or [] if isinstance(h, str)]
        bad = [h for h in hosts if not _HOST_RE.match(h)]
        if bad:
            return {"op": "error", "error": f"invalid host names: {bad[:5]}"}
        if obj["op"] == "lookup" and not hosts:
            return {"op": "error", "error": "lookup needs a non-empty hosts list"}
        return {"op": obj["op"], "hosts": hosts[:MAX_HOSTS]}
    hosts = sorted({h.lower() for h in _HOST_IN_TEXT_RE.findall(text)})
    return (
        {"op": "lookup", "hosts": hosts[:MAX_HOSTS]}
        if hosts
        else {"op": "list", "hosts": []}
    )


def answer(request: dict, inventory: dict) -> dict:
    meta = {"source": inventory["source"], "updated": inventory["updated"]}
    if request["op"] == "error":
        return {"ok": False, "op": "error", "error": request["error"], **meta}
    if request["op"] == "list":
        return {
            "ok": True,
            "op": "list",
            **meta,
            "hosts": inventory["hosts"],
            "not_found": [],
        }
    by_name = {h["host"].lower(): h for h in inventory["hosts"]}
    found = [by_name[h.lower()] for h in request["hosts"] if h.lower() in by_name]
    missing = [h for h in request["hosts"] if h.lower() not in by_name]
    return {"ok": True, "op": "lookup", **meta, "hosts": found, "not_found": missing}


def summarize(reply: dict) -> str:
    """One short line for the A2A log."""
    if not reply.get("ok"):
        return f"error: {reply.get('error')}"
    hosts = reply.get("hosts", [])
    if reply["op"] == "list":
        return f"{len(hosts)} inventory hosts: " + ", ".join(h["host"] for h in hosts)
    parts = [f"{h['host']}: owner={h['owner']}, role={h['role']}" for h in hosts]
    if reply.get("not_found"):
        parts.append(f"not in inventory: {', '.join(reply['not_found'])}")
    return "; ".join(parts) or "no hosts"
