"""Strobes MCP server — assets, findings and engagements over the public API.

Exposes a focused set of tools that wrap ``strobes_gql_client`` against the
Strobes public GraphQL endpoint (``/api/public/graphql/``, MasterKey auth).
Designed to be run as a stdio MCP server from Claude Code or any MCP host.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .client import get_context
from strobes_gql_client.exceptions import GraphQLRequestError

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("strobes_mcp")

mcp = FastMCP("strobes")

# ---- reference data (kept in docstrings too, surfaced here for callers) ----
ASSET_TYPES = {1: "Web", 2: "Mobile", 3: "Network", 4: "Cloud", 7: "Code repository"}
BUG_LEVELS = {1: "Code", 2: "Web", 3: "Mobile", 4: "Network", 5: "Cloud", 6: "Package"}
SEVERITIES = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
FINDING_STATES = {
    1: "Open", 2: "Closed/Fixed", 3: "False Positive",
    4: "Accepted Risk", 5: "Duplicate", 6: "Out of Scope",
}

_ASSET_FIELDS = ("id", "name", "target", "type", "sensitivity", "exposed",
                 "risk_score", "open_bugs_count", "tags")
_BUG_FIELDS = ("id", "title", "severity", "state", "bug_level", "cvss",
               "object_id", "exploit_available", "patch_available", "due_date")
_ENG_FIELDS = ("id", "name", "state", "scheduled_date", "delivery_date",
               "subscribed_services")


def _pick(obj: dict, fields: tuple) -> dict:
    if not isinstance(obj, dict):
        return obj
    return {k: obj.get(k) for k in fields if k in obj}


def _guard(fn):
    """Turn library/GraphQL errors into a structured tool result."""
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except GraphQLRequestError as e:
            msgs = [x.get("message", str(x)) for x in (e.errors or [])]
            return {"error": "; ".join(msgs) or str(e), "operation": e.operation_name}
        except Exception as e:  # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ------------------------------- connectivity -------------------------------
@mcp.tool()
@_guard
def strobes_whoami() -> dict:
    """Verify connectivity and show the configured Strobes host / organization,
    plus quick asset & finding counts. Call this first to confirm the server is
    wired correctly."""
    client, cfg = get_context()
    a = client.execute_query("all_assets", organization_id=cfg.organization_id,
                             page=1, page_size=1)
    b = client.execute_query("all_bugs", organization_id=cfg.organization_id,
                             page=1, page_size=1)
    return {
        "host": cfg.host,
        "organization_id": cfg.organization_id,
        "graphql_url": cfg.public_graphql_url,
        "connected": True,
        "sample_asset_returned": bool(a["data"]["allAssets"]["objects"]),
        "sample_finding_returned": bool(b["data"]["allBugs"]["objects"]),
        "reference": {"asset_types": ASSET_TYPES, "bug_levels": BUG_LEVELS,
                      "severities": SEVERITIES, "finding_states": FINDING_STATES},
    }


# ---------------------------------- assets ----------------------------------
@mcp.tool()
@_guard
def list_assets(search_query: Optional[str] = None, page: int = 1,
                page_size: int = 25) -> dict:
    """List assets in the organization.

    search_query: Strobes query-language filter, e.g. "type = 1" (web),
      "risk_score >= 70", "tags in (production)". Omit to list all.
    Returns trimmed asset records plus pagination flags.
    """
    client, cfg = get_context()
    r = client.execute_query("all_assets", organization_id=cfg.organization_id,
                             search_query=search_query, page=page, page_size=page_size)
    node = r["data"]["allAssets"]
    return {
        "assets": [_pick(o, _ASSET_FIELDS) for o in node.get("objects", [])],
        "count": len(node.get("objects", [])),
        "has_next": node.get("hasNext"),
    }


@mcp.tool()
@_guard
def get_asset(asset_id: int) -> dict:
    """Fetch a single asset by its numeric id, with full detail."""
    client, cfg = get_context()
    r = client.execute_query("all_assets", organization_id=cfg.organization_id,
                             search_query=f"id = {int(asset_id)}", page=1,
                             page_size=1)
    objs = r["data"]["allAssets"].get("objects", [])
    if not objs:
        return {"error": f"No asset found with id {asset_id}."}
    return {"asset": objs[0]}


@mcp.tool()
@_guard
def create_asset(name: str, type: int, url: Optional[str] = None,
                 hostname: Optional[str] = None, ipaddress: Optional[str] = None,
                 sensitivity: Optional[int] = None, exposed: Optional[int] = None,
                 tags: Optional[list[str]] = None,
                 cloud_type: Optional[int] = None) -> dict:
    """Create an asset.

    type (required): 1=Web, 2=Mobile, 3=Network, 4=Cloud, 7=Code repository.
    url: for web/code assets. hostname/ipaddress: for network assets.
    sensitivity: 1..4 (4=Critical). exposed: 1=Public, 2=Internal.
    tags: list of tag strings.
    """
    client, cfg = get_context()
    kwargs: dict[str, Any] = {"name": name, "type": type,
                              "organization_id": cfg.organization_id}
    for k, v in (("url", url), ("hostname", hostname), ("ipaddress", ipaddress),
                 ("sensitivity", sensitivity), ("exposed", exposed),
                 ("tags", tags), ("cloud_type", cloud_type)):
        if v is not None:
            kwargs[k] = v
    payload = client.execute_mutation("create_asset", **kwargs)
    return {"created": _pick((payload or {}).get("asset", {}), _ASSET_FIELDS)}


# --------------------------------- findings ---------------------------------
@mcp.tool()
@_guard
def list_findings(search_query: Optional[str] = None, page: int = 1,
                  page_size: int = 25) -> dict:
    """List findings (vulnerabilities).

    search_query: filter, e.g. "severity = 5" (critical), "state = 1" (open),
      "cvss >= 7", "exploit_available = true". Omit to list all.
    """
    client, cfg = get_context()
    r = client.execute_query("all_bugs", organization_id=cfg.organization_id,
                             search_query=search_query, page=page, page_size=page_size)
    node = r["data"]["allBugs"]
    return {
        "findings": [_pick(o, _BUG_FIELDS) for o in node.get("objects", [])],
        "count": len(node.get("objects", [])),
        "has_next": node.get("hasNext"),
    }


@mcp.tool()
@_guard
def create_finding(title: str, description: str, bug_level: int,
                   severity: Optional[int] = None,
                   asset_id: Optional[int] = None,
                   asset_ids: Optional[list[int]] = None,
                   mitigation: Optional[str] = None,
                   steps_to_reproduce: Optional[str] = None,
                   evidence: Optional[str] = None,
                   cve_list: Optional[list[str]] = None,
                   cwe_list: Optional[list[int]] = None,
                   tags: Optional[list[str]] = None,
                   engagement_id: Optional[str] = None,
                   details: Optional[dict] = None) -> dict:
    """Create a finding (vulnerability).

    bug_level (required): 1=Code, 2=Web, 3=Mobile, 4=Network, 5=Cloud, 6=Package.
    severity: 1=Info..5=Critical. asset_id / asset_ids: numeric id(s) of the
      asset(s) to attach the finding to (at least one is required).
    cve_list: ["CVE-2021-44228"]. cwe_list: [79]. engagement_id: attach to an
    engagement (UUID string).
    details: level-specific evidence, e.g. for web
      {"affected_endpoints": ["https://x/login"], "request": "...",
       "response": "..."}. A minimal default is supplied when omitted.
    """
    _LEVEL_FIELD = {1: "code", 2: "web", 3: "mobile", 4: "network",
                    5: "cloud", 6: "package"}
    client, cfg = get_context()
    kwargs: dict[str, Any] = {"title": title, "description": description,
                              "bug_level": bug_level,
                              "organization_id": cfg.organization_id}
    selected = list(asset_ids) if asset_ids else []
    if asset_id is not None:
        selected.append(int(asset_id))
    if selected:
        kwargs["selected_assets"] = selected
    for k, v in (("severity", severity),
                 ("mitigation", mitigation),
                 ("steps_to_reproduce", steps_to_reproduce),
                 ("evidence", evidence), ("cve_list", cve_list),
                 ("cwe_list", cwe_list), ("tags", tags),
                 ("engagement_id", engagement_id)):
        if v is not None:
            kwargs[k] = v
    level_field = _LEVEL_FIELD.get(bug_level)
    if bug_level == 2 and not (details or {}).get("affected_endpoints"):
        return {"error": "Web findings (bug_level=2) require details with a "
                "non-empty 'affected_endpoints' list, e.g. "
                "details={'affected_endpoints': ['https://host/path']}."}
    if level_field and details is not None:
        kwargs[level_field] = json.dumps(details)
    payload = client.execute_mutation("bug_create", **kwargs)
    return {"created": _pick((payload or {}).get("bug", {}), _BUG_FIELDS)}


@mcp.tool()
@_guard
def update_findings(search_query: str, state: Optional[int] = None,
                    severity: Optional[int] = None,
                    due_date: Optional[str] = None) -> dict:
    """Bulk-update findings matched by a search query.

    search_query (required): e.g. "id = 42" or "id in (1,2,3)" or "severity = 2".
    state: 1=Open, 2=Closed/Fixed, 3=False Positive, 4=Accepted Risk,
      5=Duplicate, 6=Out of Scope. severity: 1..5. due_date: "YYYY-MM-DD".
    At least one of state/severity/due_date must be given.
    """
    if state is None and severity is None and due_date is None:
        return {"error": "Provide at least one of: state, severity, due_date."}
    client, cfg = get_context()
    kwargs: dict[str, Any] = {"organization_id": cfg.organization_id,
                              "search_query": search_query}
    for k, v in (("state", state), ("severity", severity), ("due_date", due_date)):
        if v is not None:
            kwargs[k] = v
    payload = client.execute_mutation("bug_bulk_update", **kwargs)
    bugs = (payload or {}).get("bugs") or []
    return {"updated_count": len(bugs),
            "updated": [_pick(b, ("id", "state", "severity")) for b in bugs]}


@mcp.tool()
@_guard
def add_finding_comment(bug_id: int, comment: str, internal: bool = False) -> dict:
    """Add a comment to a finding. internal=True posts an internal-only note
    (honoured only for org owners/managers; others get an external comment)."""
    client, cfg = get_context()
    payload = client.execute_mutation(
        "add_bug_comment", organization_id=cfg.organization_id,
        bug_id=int(bug_id), comment=comment, internal=internal)
    c = (payload or {}).get("comment", {})
    return {"comment_id": c.get("id"), "ok": True}


# -------------------------------- engagements --------------------------------
@mcp.tool()
@_guard
def list_engagements(search_query: Optional[str] = None, page: int = 1,
                     page_size: int = 25) -> dict:
    """List engagements (security assessments)."""
    client, cfg = get_context()
    r = client.execute_query("all_engagements",
                             organization_id=cfg.organization_id,
                             search_query=search_query, page=page,
                             page_size=page_size)
    node = r["data"]["allEngagements"]
    return {
        "engagements": [_pick(o, _ENG_FIELDS) for o in node.get("objects", [])],
        "count": len(node.get("objects", [])),
        "total_count": node.get("totalCount"),
    }


@mcp.tool()
@_guard
def create_engagement(name: str, scheduled_date: str, delivery_date: str,
                      subscribed_services: list[str], plans: int = 1,
                      is_self_managed: bool = True,
                      assessment_data: Optional[str] = None,
                      executive_summary: Optional[str] = None,
                      fields: str = "{}") -> dict:
    """Create an engagement (security assessment).

    scheduled_date / delivery_date: "YYYY-MM-DD".
    subscribed_services: list of service names, e.g. ["agentic:web-app"].
    is_self_managed: True (default) for self-managed engagements; set False and
      pass a valid vendor via the platform when using a managed vendor.
    assessment_data: JSON string mapping each service to its scoped assets /
      search queries (see the skill reference for the shape). Optional.
    """
    client, cfg = get_context()
    kwargs: dict[str, Any] = {
        "organization_id": cfg.organization_id, "name": name,
        "scheduled_date": scheduled_date, "delivery_date": delivery_date,
        "subscribed_services": subscribed_services, "plans": plans,
        "fields": fields, "document_ids": [], "is_self_managed": is_self_managed,
    }
    if assessment_data is not None:
        kwargs["assessment_data"] = assessment_data
    if executive_summary is not None:
        kwargs["executive_summary"] = executive_summary
    payload = client.execute_mutation("create_engagement", **kwargs)
    eng = (payload or {}).get("engagement") or payload or {}
    return {"created": _pick(eng if isinstance(eng, dict) else {}, _ENG_FIELDS)}


@mcp.tool()
@_guard
def add_engagement_comment(engagement_id: str, comment: str) -> dict:
    """Add a comment to an engagement (by UUID)."""
    client, cfg = get_context()
    payload = client.execute_mutation(
        "add_engagement_comment", organization_id=cfg.organization_id,
        engagement_id=engagement_id, comment=comment)
    c = (payload or {}).get("comment", {})
    return {"comment_id": c.get("id"), "ok": True}


@mcp.tool()
@_guard
def list_comments(bug_id: Optional[int] = None,
                  engagement_id: Optional[str] = None,
                  page: int = 1, page_size: int = 25) -> dict:
    """List comments on a finding (bug_id) or an engagement (engagement_id)."""
    if bug_id is None and engagement_id is None:
        return {"error": "Provide either bug_id or engagement_id."}
    client, cfg = get_context()
    kwargs: dict[str, Any] = {"organization_id": cfg.organization_id,
                              "page": page, "page_size": page_size}
    if bug_id is not None:
        kwargs["bug_id"] = int(bug_id)
    if engagement_id is not None:
        kwargs["engagement_id"] = engagement_id
    r = client.execute_query("all_comments", **kwargs)
    node = r["data"]["allComments"]
    return {"comments": node.get("objects", []),
            "total_count": node.get("totalCount")}


def main() -> None:
    """Console entry point — runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
