"""End-to-end test for strobes-mcp against a live Strobes backend.

Configure via env (the harness points it at the local dockerized stack):
  STROBES_HOST, STROBES_API_TOKEN, STROBES_ORGANIZATION_ID
  STROBES_BASE_URL (e.g. http://localhost), STROBES_TENANT_HOST (Host header)
Run:  uv run --with mcp --with requests --with sgqlc python tests/test_e2e.py
"""
import os, sys, json, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from strobes_mcp import server  # noqa: E402

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}"[:200])

def main():
    r = server.strobes_whoami()
    check("whoami.connected", r.get("connected") is True, json.dumps(r)[:120])

    r = server.list_assets(page_size=3)
    check("list_assets", "assets" in r and r.get("count", 0) >= 0, f"count={r.get('count')}")

    r = server.list_findings(page_size=3)
    check("list_findings", "findings" in r, f"count={r.get('count')}")

    r = server.list_engagements(page_size=3)
    check("list_engagements", "engagements" in r, f"count={r.get('count')}")

    stamp = int(time.time())
    r = server.create_asset(name=f"mcp-e2e-asset-{stamp}", type=1,
                            url=f"https://e2e-{stamp}.example.com",
                            sensitivity=2, exposed=1, tags=["mcp-e2e"])
    aid = (r.get("created") or {}).get("id")
    check("create_asset", bool(aid), f"id={aid} err={r.get('error')}")

    if aid:
        ga = server.get_asset(int(aid))
        check("get_asset", (ga.get("asset") or {}).get("id") == aid, json.dumps(ga)[:100])

    r = server.create_finding(title=f"mcp-e2e-finding-{stamp}",
                              description="Automated e2e finding", bug_level=2,
                              severity=3, asset_id=int(aid) if aid else None,
                              details={"affected_endpoints": [f"https://e2e-{stamp}.example.com/x"],
                                       "request": "GET /x HTTP/1.1", "response": "HTTP/1.1 200 OK"})
    fid = (r.get("created") or {}).get("id")
    check("create_finding", bool(fid), f"id={fid} err={r.get('error')}")

    if fid:
        r = server.add_finding_comment(bug_id=int(fid), comment="e2e comment")
        check("add_finding_comment", r.get("ok") is True, json.dumps(r)[:120])

        r = server.update_findings(search_query=f"id = {fid}", state=3)
        check("update_findings", r.get("updated_count", 0) >= 1, json.dumps(r)[:120])

        r = server.list_comments(bug_id=int(fid))
        check("list_comments", "comments" in r, f"n={len(r.get('comments', []))}")

    ce = server.create_engagement(name=f"mcp-e2e-eng-{stamp}",
                                  scheduled_date="2026-10-10", delivery_date="2026-10-20",
                                  subscribed_services=["agentic:web-app"])
    eid = (ce.get("created") or {}).get("id")
    check("create_engagement", bool(eid), f"id={eid} err={ce.get('error')}")
    if eid:
        check("add_engagement_comment",
              server.add_engagement_comment(engagement_id=eid, comment="e2e").get("ok") is True)

    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    if FAIL:
        print("FAILURES:", FAIL); sys.exit(1)

if __name__ == "__main__":
    main()
