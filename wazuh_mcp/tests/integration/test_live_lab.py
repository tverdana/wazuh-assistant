"""Live checks against the running Wazuh lab (skipped when it is not up).

lab/lab.sh up && lab/lab.sh users && lab/lab.sh alerts
uv run pytest tests/integration -m live
"""

import socket

import pytest
from mcp.client import Client

from wazuh_mcp import server
from wazuh_mcp.clients import WazuhApi, WazuhIndexer
from wazuh_mcp.settings import load_settings


def _port_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def _lab_up() -> bool:
    try:
        load_settings()
    except RuntimeError:
        return False
    return _port_open(55000) and _port_open(9200)


pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not _lab_up(), reason="Wazuh lab not running"),
]


@pytest.fixture(autouse=True)
def live_clients():
    settings = load_settings()
    server.set_clients(WazuhApi(settings), WazuhIndexer(settings))


async def test_agents_have_expected_lab_states():
    out = await server.list_agents()
    status = {a.name: a.status for a in out.agents}
    assert status["lab-web-01"] == "active"
    assert status["lab-db-01"] == "disconnected"


async def test_explain_bruteforce_rule():
    out = await server.explain_rule(5712)
    assert out.level == 10
    assert out.mitre[0].id == "T1110" and out.mitre[0].name == "Brute Force"


async def test_sca_summary_has_cis_policy():
    out = await server.sca_summary("lab-web-01")
    assert out.policies and out.policies[0].total_checks > 0


async def test_alerts_and_injection_flagging():
    out = await server.list_alerts(
        since="7d", min_level=5, agent="lab-web-01", limit=50
    )
    assert out.returned > 0
    for alert in out.alerts:
        if (
            alert.command
            and "ignore all previous instructions" in alert.command.lower()
        ):
            assert alert.injection_suspected


async def test_alert_stats_by_agent():
    out = await server.alert_stats(group_by="agent", since="7d")
    assert "lab-web-01" in {b.key for b in out.buckets}


@pytest.mark.skipif(not _port_open(8020), reason="wazuh-mcp not running on :8020")
async def test_streamable_http_endpoint():
    async with Client("http://127.0.0.1:8020/mcp") as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "list_alerts" in names
        result = await client.call_tool("list_agents", {"status": "disconnected"})
        assert result.structured_content["agents"][0]["name"] == "lab-db-01"
