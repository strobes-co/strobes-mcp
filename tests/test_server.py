"""Tools exercised through a real in-memory MCP client session (mocked HTTP)."""

import json

import httpx
import pytest
import respx
from mcp.shared.memory import create_connected_server_and_client_session

from strobes_mcp import server
from conftest import GQL, ORG


@pytest.fixture(autouse=True)
def fresh_session():
    server.SESSION.__init__()
    yield


async def call(tool, **args):
    async with create_connected_server_and_client_session(server.mcp._mcp_server) as s:
        res = await s.call_tool(tool, args)
        text = res.content[0].text if res.content else ""
        return res, (json.loads(text) if not res.isError else text)


def gql_router(handlers, seen=None):
    """Dispatch mocked GraphQL by root field; records request bodies in `seen`."""
    def handle(request):
        body = json.loads(request.content)
        if seen is not None:
            seen.append(body)
        for key, resp in handlers.items():
            if key in body["query"]:
                out = resp(body) if callable(resp) else resp
                return out if isinstance(out, httpx.Response) else httpx.Response(200, json=out)
        return httpx.Response(200, json={"errors": [{"message": "unmocked"}]})
    return handle


async def test_tool_catalog():
    async with create_connected_server_and_client_session(server.mcp._mcp_server) as s:
        init_tools = (await s.list_tools()).tools
        names = {t.name for t in init_tools}
        assert {"strobes_login", "list_findings", "get_finding", "update_findings",
                "create_engagement", "strobes_reference"} <= names
        for t in init_tools:
            assert t.annotations is not None and t.description, t.name
        by = {t.name: t.annotations for t in init_tools}
        assert by["list_findings"].readOnlyHint and not by["create_finding"].readOnlyHint
        assert by["update_findings"].destructiveHint
        prompts = {p.name for p in (await s.list_prompts()).prompts}
        assert {"triage_findings", "asset_risk_summary"} <= prompts


async def test_requires_login():
    res, text = await call("list_findings")
    assert res.isError and "strobes_login" in text


@respx.mock
async def test_list_findings_builds_query_and_labels(signed_in):
    seen = []
    respx.post(GQL).mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {
        "hasNext": True, "objects": [{"id": "7", "title": "SQLi", "severity": 5, "state": 0,
                                      "bugLevel": 2, "asset": {"id": "3", "name": "app"}}]}}}}, seen))
    _, out = await call("list_findings", severity=["critical", "high"], open_only=True,
                        search_query="cvss >= 7")
    v = seen[0]["variables"]
    assert v["org"] == ORG
    assert v["q"] == "cvss >= 7 and severity in (5, 4) and state in (0, 1)"
    f = out["findings"][0]
    assert (f["severity"], f["state"], f["level"]) == ("critical", "new", "web")
    assert out["next_page"] == 2 and out["query"] == v["q"]


@respx.mock
async def test_state_codes_match_the_backend_model(signed_in):
    """Regression: the old server mapped 3=False positive etc.; the model says 3=Duplicate."""
    seen = []
    respx.post(GQL).mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {"objects": []}}}}, seen))
    await call("list_findings", state=["accepted_risk", "duplicate", "not_applicable"])
    assert seen[0]["variables"]["q"] == "state in (6, 3, 4)"


@respx.mock
async def test_get_finding_detail(signed_in):
    respx.post(GQL).mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {"objects": [{
        "id": "42", "title": "XSS", "severity": 4, "state": 1, "bugLevel": 2,
        "description": "d", "cve": [{"cveId": "CVE-2024-1"}], "cwe": [{"cweId": "79", "type": "XSS"}],
        "bugTags": [{"name": "prod"}]}]}}}}))
    _, out = await call("get_finding", finding_id=42)
    assert out["cve"] == ["CVE-2024-1"] and out["cwe"] == ["CWE-79: XSS"] and out["tags"] == ["prod"]
    assert out["web_url"].endswith(f"/organizations/{ORG}/apps/ctem/findings/42")


@respx.mock
async def test_get_finding_not_found(signed_in):
    respx.post(GQL).mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {"objects": []}}}}))
    res, text = await call("get_finding", finding_id=1)
    assert res.isError and "No finding with id 1" in text


@respx.mock
async def test_update_findings_checks_matches_first(signed_in):
    seen = []
    respx.post(GQL).mock(side_effect=gql_router({
        "bugBulkUpdate(": {"data": {"bugBulkUpdate": {"bugs": [{"id": "1", "state": 2, "severity": 3}]}}},
        "allBugs(": {"data": {"allBugs": {"hasNext": False, "objects": [{"id": "1"}]}}},
    }, seen))
    _, out = await call("update_findings", search_query="id = 1", state="resolved",
                        confirm_seconds=0)
    mutation = next(b for b in seen if "bugBulkUpdate" in b["query"])
    assert mutation["variables"] == {"org": ORG, "q": "id = 1", "state": 2}
    assert out["submitted"] == 1


@respx.mock
async def test_update_findings_reports_applied_vs_pending(signed_in, monkeypatch):
    """Bulk updates are async server-side: only claim what actually changed."""
    async def no_sleep(*_a, **_k):
        return None
    monkeypatch.setattr(server, "_sleep", no_sleep)
    states = iter([0, 0, 2])  # still "new" twice, then resolved

    def bugs(body):
        if "id in (" in (body["variables"].get("q") or ""):
            return {"data": {"allBugs": {"objects": [{"id": "1", "state": next(states, 2),
                                                      "severity": 3}]}}}
        return {"data": {"allBugs": {"hasNext": False, "objects": [{"id": "1"}]}}}

    respx.post(GQL).mock(side_effect=gql_router({
        "bugBulkUpdate(": {"data": {"bugBulkUpdate": {"bugs": [{"id": "1", "state": 0, "severity": 3}]}}},
        "allBugs(": bugs}))
    _, out = await call("update_findings", search_query="id = 1", state="resolved",
                        confirm_seconds=30)
    assert out["applied"] == 1 and "pending" not in out
    assert out["updated"][0]["state"] == "resolved"

    states = iter([0] * 100)
    _, out = await call("update_findings", search_query="id = 1", state="resolved",
                        confirm_seconds=0)
    assert out["applied"] == 0 and out["pending"][0]["state"] == "new" and "approval" in out["note"]


@respx.mock
async def test_update_findings_refuses_large_or_empty_matches(signed_in):
    route = respx.post(GQL)
    route.mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {"hasNext": True,
                                                                          "objects": [{"id": "1"}] * 200}}}}))
    res, text = await call("update_findings", search_query="severity = 1", state="resolved")
    assert res.isError and "allow_many" in text
    assert all("bugBulkUpdate" not in json.loads(c.request.content)["query"] for c in route.calls)

    route.mock(side_effect=gql_router({"allBugs(": {"data": {"allBugs": {"objects": []}}}}))
    res, text = await call("update_findings", search_query="id = 999", state="resolved")
    assert res.isError and "nothing changed" in text

    res, text = await call("update_findings", search_query="id = 1")
    assert res.isError and "at least one" in text


@respx.mock
async def test_create_finding_web_needs_endpoints_and_sends_level_json(signed_in):
    res, text = await call("create_finding", title="t", description="d", level="web",
                           asset_ids=[3])
    assert res.isError and "affected_endpoints" in text

    seen = []
    respx.post(GQL).mock(side_effect=gql_router({"bugCreate(": {"data": {"bugCreate": {"bug": {
        "id": "9", "title": "t", "severity": 4, "state": 0, "bugLevel": 2}}}}}, seen))
    _, out = await call("create_finding", title="t", description="d", level="web", asset_ids=[3],
                        severity="high", details={"affected_endpoints": ["https://a/x"]})
    v = seen[0]["variables"]
    assert v["level"] == 2 and v["severity"] == 4 and v["assets"] == [3]
    assert json.loads(v["web"]) == {"affected_endpoints": ["https://a/x"], "request": "",
                                    "response": ""}
    assert out["created"]["id"] == "9"


@respx.mock
async def test_list_assets_type_filter_and_labels(signed_in):
    seen = []
    respx.post(GQL).mock(side_effect=gql_router({"allAssets(": {"data": {"allAssets": {
        "hasNext": False, "objects": [{"id": "1", "name": "app", "type": 1, "sensitivity": 4,
                                       "exposed": 1, "tags": [{"name": "prod"}]}]}}}}, seen))
    _, out = await call("list_assets", type=[1, 7], search_query="risk_score >= 70")
    assert seen[0]["variables"]["q"] == "risk_score >= 70 and type in (1, 7)"
    a = out["assets"][0]
    assert (a["type"], a["sensitivity"], a["exposure"], a["tags"]) == ("web", "critical", "high", ["prod"])


@respx.mock
async def test_comments_and_engagements(signed_in):
    respx.post(GQL).mock(side_effect=gql_router({
        "allComments(": {"data": {"allComments": {"totalCount": 1, "objects": [
            {"id": "1", "comment": "hi", "commentedBy": {"email": "a@b.c"}}]}}},
        "allEngagements(": {"data": {"allEngagements": {"totalCount": 1, "objects": [
            {"id": "e", "name": "Q3 pentest", "state": 2}]}}},
    }))
    _, out = await call("list_comments", finding_id=5)
    assert out["comments"][0]["by"] == "a@b.c"
    res, text = await call("list_comments")
    assert res.isError
    _, out = await call("list_engagements")
    assert out["engagements"][0]["state"] == "in_progress" and out["total"] == 1


@respx.mock
async def test_known_allbugs_backend_bug_is_explained(signed_in):
    respx.post(GQL).respond(200, json={"errors": [{"message": (
        "Field Bug.connector cannot be both deferred and traversed using select_related "
        "at the same time.")}], "data": {"allBugs": {"objects": None}}})
    res, text = await call("list_findings")
    assert res.isError and "known bug" in text


async def test_session_tools_refuse_remote_clients(signed_in, monkeypatch):
    monkeypatch.setenv("STROBES_MCP_TRANSPORT", "streamable-http")
    res, text = await call("strobes_logout")
    assert res.isError and "only available when the server runs locally" in text
    assert server.resolve_profile().complete


async def test_reference_is_offline():
    _, out = await call("strobes_reference")
    assert out["finding_state"]["3"] == "duplicate" and out["asset_exposure"]["1"] == "high"
