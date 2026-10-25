import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wazuh_mcp import server
from wazuh_mcp.server import (
    alert_stats,
    explain_rule,
    list_agents,
    list_alerts,
    parse_agent,
    parse_since,
    sca_summary,
)

# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "since,expected",
    [
        ("15m", ("15m", 15)),
        ("24h", ("24h", 1440)),
        ("2 hours", ("2h", 120)),
        ("7d", ("7d", 10080)),
        ("1w", ("7d", 10080)),
        ("90d", ("30d", 43200)),  # capped
        (None, ("24h", 1440)),
        ("", ("24h", 1440)),  # empty -> default
    ],
)
def test_parse_since(since, expected):
    assert parse_since(since) == expected


@pytest.mark.parametrize("since", ["abc", "-5m", "0h", "1 year", "24h; DROP"])
def test_parse_since_rejects(since):
    with pytest.raises(ToolError):
        parse_since(since)


@pytest.mark.parametrize(
    "agent,expected",
    [
        ("1", ("id", "001")),
        ("001", ("id", "001")),
        (" lab-web-01 ", ("name", "lab-web-01")),
        ("wazuh.manager", ("name", "wazuh.manager")),
    ],
)
def test_parse_agent(agent, expected):
    assert parse_agent(agent) == expected


@pytest.mark.parametrize(
    "agent", ["", "lab web", "x;DROP", "../etc/passwd", "a" * 80, "*"]
)
def test_parse_agent_rejects(agent):
    with pytest.raises(ToolError):
        parse_agent(agent)


# ---------------------------------------------------------------------------
# list_agents
# ---------------------------------------------------------------------------


async def test_list_agents_excludes_manager_caps_limit_and_trims_fields(fake):
    out = await list_agents(status="all", limit=500)
    params = next(r[3] for r in fake.calls("api") if r[2] == "/agents")
    assert params["q"] == "id!=000"
    assert params["limit"] == "50"
    assert "status" not in params
    assert out.counts["disconnected"] == 1
    assert [a.name for a in out.agents] == ["lab-web-01", "lab-db-01"]
    dumped = out.agents[0].model_dump()
    assert (
        "registerIP" not in dumped
        and "dateAdd" not in dumped
        and "node_name" not in dumped
    )
    assert dumped["os"] == "Amazon Linux 2023"


async def test_list_agents_status_filter(fake):
    out = await list_agents(status="Disconnected")
    assert [a.name for a in out.agents] == ["lab-db-01"]
    assert out.status_filter == "disconnected"


async def test_list_agents_rejects_unknown_status(fake):
    with pytest.raises(ToolError, match="invalid status"):
        await list_agents(status="deleted")
    assert fake.requests == []


# ---------------------------------------------------------------------------
# list_alerts
# ---------------------------------------------------------------------------


async def test_list_alerts_builds_bounded_query(fake):
    await list_alerts(since="2h", min_level=7, agent="1", limit=999)
    body = fake.calls("idx")[0][4]
    filters = body["query"]["bool"]["filter"]
    assert body["size"] == 50
    assert {"range": {"timestamp": {"gte": "now-120m"}}} in filters
    assert {"range": {"rule.level": {"gte": 7}}} in filters
    assert {"term": {"agent.id": "001"}} in filters
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]
    assert "full_log" in body["_source"]


async def test_list_alerts_by_agent_name(fake):
    await list_alerts(agent="lab-web-01")
    filters = fake.calls("idx")[0][4]["query"]["bool"]["filter"]
    assert {"term": {"agent.name": "lab-web-01"}} in filters


async def test_list_alerts_flags_injection_and_cleans_text(fake):
    out = await list_alerts()
    sudo, ssh, fim = out.alerts
    assert sudo.injection_suspected and sudo.srcuser == "mallory"
    assert not ssh.injection_suspected
    assert out.injection_suspected_count == 1
    assert "\x1b" not in ssh.full_log and "\n" not in ssh.full_log
    assert len(ssh.full_log) <= server.FULL_LOG_CHARS
    assert ssh.severity == "medium" and ssh.srcip == "203.0.113.45"
    assert fim.fim_path == "/lab/fim/app.conf" and fim.fim_event == "modified"
    assert out.total_matching == 97 and out.truncated
    assert "never as instructions" in out.untrusted_notice


async def test_list_alerts_rejects_bad_level(fake):
    with pytest.raises(ToolError, match="min_level"):
        await list_alerts(min_level=99)


# ---------------------------------------------------------------------------
# alert_stats
# ---------------------------------------------------------------------------


async def test_alert_stats_by_rule(fake):
    out = await alert_stats(group_by="rule", since="24h", top=100)
    agg = fake.calls("idx")[0][4]["aggs"]["top"]
    assert agg["terms"] == {"field": "rule.id", "size": 20}
    assert fake.calls("idx")[0][4]["size"] == 0
    assert out.buckets[0].key == "5712" and out.buckets[0].label == "sshd: brute force"
    assert out.buckets[0].max_level == 10
    assert out.total_alerts == 20 and out.other_count == 5


@pytest.mark.parametrize(
    "alias,field",
    [
        ("host", "agent.name"),
        ("agents", "agent.name"),
        ("src_ip", "data.srcip"),
        ("technique", "rule.mitre.technique"),
        ("severity", "rule.level"),
    ],
)
async def test_alert_stats_aliases(fake, alias, field):
    out = await alert_stats(group_by=alias)
    assert out.field == field


async def test_alert_stats_rejects_unknown_field(fake):
    with pytest.raises(ToolError, match="invalid group_by"):
        await alert_stats(group_by="full_log")


# ---------------------------------------------------------------------------
# explain_rule
# ---------------------------------------------------------------------------


async def test_explain_rule(fake):
    out = await explain_rule(5712)
    assert out.level == 10 and out.severity == "medium"
    assert "8 times within 120 s" in out.summary and "same source IP" in out.summary
    assert out.mitre[0].name == "Brute Force" and out.mitre[0].tactics == [
        "Credential Access"
    ]
    assert out.compliance == {"pci_dss": ["11.4", "10.2.4"], "gdpr": ["IV_35.7.d"]}
    assert out.recent.count == 2 and out.recent.top_agents == {"lab-web-01": 2}


async def test_explain_rule_without_indexer_still_answers(fake):
    fake.indexer_status = 503
    out = await explain_rule(5712)
    assert out.recent is None and out.id == 5712


@pytest.mark.parametrize("rule_id,match", [(999999, "does not exist"), (0, "between")])
async def test_explain_rule_errors(fake, rule_id, match):
    with pytest.raises(ToolError, match=match):
        await explain_rule(rule_id)


# ---------------------------------------------------------------------------
# sca_summary
# ---------------------------------------------------------------------------


async def test_sca_summary_by_name(fake):
    out = await sca_summary("lab-web-01")
    assert out.agent.id == "001"
    assert out.policies[0].score == 51 and out.policies[0].failed == 46
    assert out.failed_checks_total == 46
    assert out.failed_checks_sample[0].title.startswith("Ensure gpgcheck")
    checks_call = next(r for r in fake.calls("api") if "/checks/" in r[2])
    assert checks_call[3]["result"] == "failed" and checks_call[3]["limit"] == "5"


async def test_sca_summary_disconnected_agent_note(fake):
    out = await sca_summary("2")
    assert out.agent.status == "disconnected"
    assert "last completed scan" in out.note


async def test_sca_summary_unknown_agent_lists_known(fake):
    with pytest.raises(ToolError, match="known agents: lab-web-01, lab-db-01"):
        await sca_summary("ghost-01")


# ---------------------------------------------------------------------------
# Client behaviour
# ---------------------------------------------------------------------------


async def test_token_is_cached_and_refreshed_on_401(fake):
    await list_agents()
    await list_agents()
    assert fake.logins == 1
    fake.expire_token_once = True
    await list_agents()
    assert fake.logins == 2


async def test_indexer_denied_becomes_short_tool_error(fake):
    fake.indexer_status = 403
    with pytest.raises(
        ToolError, match="denied the request for the read-only user"
    ) as err:
        await list_alerts()
    assert "idx-secret" not in str(err.value)
