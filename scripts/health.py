"""Demo health check (LAB only, read-only identities only).

    uv run --project wazuh_mcp python -I scripts/health.py [--wait SECONDS]

Prints one table row per check. Required checks are retried until they pass or
--wait expires; asset_agent and the playground are informational because they
are started by hand in two foreground terminals. Exit code 1 if a required
check fails. No secret is ever printed.
"""

import argparse
import asyncio
import subprocess
import sys
import time
from pathlib import Path

import httpx
from mcp.client import Client

from wazuh_mcp.clients import WazuhApi, WazuhIndexer, _ssl_context
from wazuh_mcp.knowledge import load_bundle
from wazuh_mcp.settings import load_settings

ROOT = Path(__file__).resolve().parents[1]
LAB_CONTAINERS = [
    "wazuh-lab-wazuh.manager-1",
    "wazuh-lab-wazuh.indexer-1",
    "wazuh-lab-wazuh.dashboard-1",
    "lab-web-01",
]
OK, FAIL, INFO = "✅ OK", "❌ FAIL", "⏸  TODO"


def docker_states() -> dict[str, str]:
    out = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)


async def check_containers():
    states = docker_states()
    down = [c for c in LAB_CONTAINERS if states.get(c) != "running"]
    if down:
        return FAIL, f"not running: {', '.join(down)}"
    db = states.get("lab-db-01", "missing")
    return OK, f"{len(LAB_CONTAINERS)} running; lab-db-01 {db} (stopped on purpose)"


async def check_agents(api: WazuhApi):
    items, _ = await api.items("/agents", q="id!=000", select="name,status")
    status = {a["name"]: a["status"] for a in items}
    detail = ", ".join(f"{n} {s}" for n, s in sorted(status.items()))
    good = (
        status.get("lab-web-01") == "active"
        and status.get("lab-db-01") == "disconnected"
    )
    return (OK if good else FAIL), detail or "no agents"


async def check_write_denied(settings, api: WazuhApi):
    token = await api._get_token()
    # same pinned self-signed API certificate as the MCP client
    ctx = _ssl_context(settings.api_ca, check_hostname=False)
    async with httpx.AsyncClient(verify=ctx, timeout=10) as client:
        resp = await client.put(
            f"{settings.api_url}/agents/restart",
            params={"agents_list": "001"},
            headers={"Authorization": f"Bearer {token}"},
        )
    return (
        OK if resp.status_code == 403 else FAIL
    ), f"PUT /agents/restart as read-only user -> HTTP {resp.status_code}"


async def _count(indexer: WazuhIndexer, rule_id: str, minutes: int) -> int:
    res = await indexer.search(
        {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.id": rule_id}},
                        {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                    ]
                }
            },
        }
    )
    return int(res["hits"]["total"]["value"])


async def check_fresh_alerts(indexer: WazuhIndexer):
    brute = await _count(indexer, "5712", 30)
    sudo = await _count(indexer, "5405", 30)
    detail = f"last 30 min: {brute}x rule 5712 (ssh brute force), {sudo}x rule 5405 (sudo, carries injection text)"
    return (OK if brute and sudo else FAIL), detail


async def check_mcp():
    async with Client("http://127.0.0.1:8020/mcp") as client:
        tools = sorted(t.name for t in (await client.list_tools()).tools)
        result = await client.call_tool("list_agents", {"status": "all"})
    good = len(tools) == 7 and not result.is_error
    return (
        (OK if good else FAIL),
        f"{len(tools)} read-only tools; list_agents call {'ok' if not result.is_error else 'failed'}",
    )


async def check_knowledge():
    concepts = load_bundle()
    return OK, f"knowledge/ OKF bundle: {len(concepts)} concepts"


async def check_gemini_key():
    env = ROOT / ".env"
    text = env.read_text() if env.is_file() else ""
    has = any(
        line.startswith("GEMINI_API_KEY=") and line.strip() != "GEMINI_API_KEY="
        for line in text.splitlines()
    )
    return (
        (OK if has else FAIL),
        ".env has GEMINI_API_KEY (value not shown)"
        if has
        else ".env lacks GEMINI_API_KEY",
    )


async def check_url(url: str, hint: str):
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url)
        if resp.status_code == 200:
            return OK, f"{url} -> 200"
    except httpx.HTTPError:
        pass
    return INFO, f"not running yet — {hint}"


async def run_checks(settings, api, indexer) -> list[tuple[str, bool, str, str]]:
    checks = [
        ("Lab containers", True, check_containers()),
        ("Wazuh agents", True, check_agents(api)),
        ("Read-only enforced", True, check_write_denied(settings, api)),
        ("Fresh alerts indexed", True, check_fresh_alerts(indexer)),
        ("MCP server :8020", True, check_mcp()),
        ("Knowledge bundle", True, check_knowledge()),
        ("Gemini credentials", True, check_gemini_key()),
        (
            "asset_agent :8030",
            False,
            check_url(
                "http://127.0.0.1:8030/.well-known/agent-card.json",
                "start it in terminal 1",
            ),
        ),
        (
            "Playground :8502",
            False,
            check_url("http://127.0.0.1:8502/list-apps", "start it in terminal 2"),
        ),
    ]
    rows = []
    for name, required, coro in checks:
        try:
            status, detail = await coro
        except Exception as e:  # report, never crash the table
            status, detail = FAIL, f"{type(e).__name__}: {str(e)[:100]}"
        rows.append((name, required, status, detail))
    return rows


async def main(wait: int) -> int:
    settings = load_settings()
    deadline = time.monotonic() + wait
    while True:
        api, indexer = WazuhApi(settings), WazuhIndexer(settings)
        rows = await run_checks(settings, api, indexer)
        await api.aclose()
        await indexer.aclose()
        failed = [r for r in rows if r[1] and r[2] == FAIL]
        if not failed or time.monotonic() >= deadline:
            break
        print(f"  waiting for: {', '.join(r[0] for r in failed)} ...", flush=True)
        await asyncio.sleep(10)

    width = max(len(r[0]) for r in rows)
    print()
    print(f"  {'CHECK'.ljust(width)}  STATUS    DETAIL")
    print(f"  {'-' * width}  --------  {'-' * 60}")
    for name, _, status, detail in rows:
        print(f"  {name.ljust(width)}  {status.ljust(8)}  {detail}")
    print()
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--wait", type=int, default=0, help="retry required checks for N seconds"
    )
    sys.exit(asyncio.run(main(parser.parse_args().wait)))
