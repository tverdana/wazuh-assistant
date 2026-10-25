"""The server can only read: no write tools, no write HTTP calls, all tools
annotated read-only on the MCP wire."""

import pytest
from mcp.client import Client

from wazuh_mcp import server
from wazuh_mcp.clients import WazuhApi, WazuhError, WazuhIndexer
from wazuh_mcp.server import (
    alert_stats,
    explain_rule,
    list_agents,
    list_alerts,
    sca_summary,
)

EXPECTED_TOOLS = {
    "list_agents",
    "list_alerts",
    "alert_stats",
    "explain_rule",
    "sca_summary",
}


async def test_every_http_call_is_a_read(fake):
    await list_agents()
    await list_alerts(agent="lab-web-01")
    await alert_stats(group_by="agent")
    await explain_rule(5712)
    await sca_summary("lab-web-01")

    for service, method, path, _, _ in fake.requests:
        if service == "api":
            assert method == "GET" or (method, path) == (
                "POST",
                "/security/user/authenticate",
            )
        else:
            assert (method, path) == ("POST", "/wazuh-alerts-*/_search")


def test_clients_have_no_write_methods():
    for cls in (WazuhApi, WazuhIndexer):
        for name in ("post", "put", "patch", "delete", "request", "send"):
            assert not hasattr(cls, name), f"{cls.__name__}.{name} must not exist"


@pytest.mark.parametrize(
    "path",
    [
        "/security/users",
        "/active-response",
        "/manager/restart",
        "/agents/../security/users",
        "/cluster/restart",
    ],
)
async def test_api_client_blocks_non_allowlisted_paths(fake, path):
    api, _ = server._get_clients()
    with pytest.raises(WazuhError, match="blocked"):
        await api.get(path)
    assert fake.requests == []


async def test_mcp_wire_exposes_only_read_only_tools(fake):
    async with Client(server.mcp) as client:
        tools = (await client.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        for tool in tools:
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False
            assert tool.output_schema is not None  # structured output

        result = await client.call_tool("list_agents", {"status": "active"})
        assert not result.is_error
        assert result.structured_content["agents"][0]["name"] == "lab-web-01"

        bad = await client.call_tool("alert_stats", {"group_by": "full_log"})
        assert bad.is_error and "invalid group_by" in bad.content[0].text
