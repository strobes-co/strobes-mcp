"""Strobes MCP server — assets, findings and engagements.

Query and manage the Strobes platform from any MCP host: search assets and
vulnerabilities with the Strobes query language, triage findings, comment, and
create assets / findings / engagements. Browser sign-in is shared with the
Strobes CLI. Companion to strobes-agents-mcp (AI agents & workspaces).
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from . import __version__, auth, render
from . import queries as Q
from .api import ENV_INCOMPLETE, NOT_SIGNED_IN, AuthError, StrobesAPI, StrobesError
from .config import (ConfigError, Profile, clear_login, list_profiles, resolve_profile,
                     set_current_profile)

log = logging.getLogger("strobes_agents_mcp")
_sleep = asyncio.sleep  # indirection so tests can fast-forward polling

INSTRUCTIONS = """\
Strobes is a vulnerability / exposure management platform. These tools read and
manage its assets, findings (vulnerabilities) and engagements (assessments).

Start with `strobes_whoami`. If it says you're not signed in, call `strobes_login`,
show the user the link and code, then call `strobes_login_status` until approved.

Searching: `list_assets` / `list_findings` / `list_engagements` take a DjangoQL
`search_query`: `severity = 5 and state in (0, 1)` (open criticals), `cvss >= 7 and
exploit_available = "true"`, `title ~ "sql"` (contains), `asset.id = 12`,
`asset_tags = "prod"`, `type = 1` (web assets). Strings in quotes, yes/no flags are
strings, relations use dots, no `like`. Codes: severity 1=info…5=critical; finding state
0=new 1=active 2=resolved 3=duplicate 4=not applicable 5=committed 6=accepted risk
7=won't fix; asset type 1=web 2=mobile 3=network 4=cloud 7=code repo. Prefer the
`severity` / `state` / `open_only` / `type` parameters over writing codes by hand;
`strobes_reference` has every table and more examples.

Changes are real: `update_findings` applies to EVERY finding its query matches —
check the match with `list_findings` first and confirm with the user.
"""

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                     openWorldHint=True)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                        openWorldHint=True)
WRITE_IDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                   idempotentHint=True, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                              idempotentHint=True, openWorldHint=True)

SearchQuery = Annotated[Optional[str], Field(description=(
    "DjangoQL filter, e.g. 'cvss >= 7 and exploit_available = \"true\"', 'title ~ \"sql\"', "
    "'asset.id = 12'. Omit for all."))]
Page = Annotated[int, Field(ge=1)]
PageSize = Annotated[int, Field(ge=1, le=100)]


# --------------------------------------------------------------------------
# session state
# --------------------------------------------------------------------------
class Session:
    """Per-process credentials, API clients and the in-flight browser login."""

    def __init__(self) -> None:
        self.profile_override: str | None = None
        self.login: auth.DeviceLogin | None = None
        self.login_task: asyncio.Task | None = None
        # Clients are shared by concurrent requests, so they are never closed while
        # the process runs (closing one could break another request mid-call); the
        # cache is bounded and evicted clients are just dropped.
        self._clients: OrderedDict[tuple, StrobesAPI] = OrderedDict()

    def profile(self, ctx: Context | None = None) -> Profile:
        hdr = _request_profile(ctx)
        if hdr is not None:
            return hdr
        if os.getenv("STROBES_MCP_REQUIRE_HEADER_AUTH"):
            raise AuthError("This server needs per-request credentials: send "
                            "`Authorization: Bearer <Strobes MasterKey>` plus "
                            "`X-Strobes-Url` and `X-Strobes-Organization-Id` headers.")
        return resolve_profile(self.profile_override)

    def api(self, ctx: Context | None = None) -> StrobesAPI:
        p = self.profile(ctx)
        if not p.complete:
            msg = ENV_INCOMPLETE if p.source == "env-incomplete" else NOT_SIGNED_IN
            if self.login and self.login.status == "pending":
                msg = ("Sign-in is in progress — ask the user to approve it at "
                       f"{self.login.verification_url} (code {self.login.user_code}), "
                       "then call `strobes_login_status`.")
            raise AuthError(msg)
        key = (p.graphql_url, p.master_key, p.org_id, p.verify_tls, p.tenant_host)
        client = self._clients.get(key)
        if client is None or client.closed:
            client = StrobesAPI(p)
            self._clients[key] = client
            while len(self._clients) > MAX_CLIENTS:
                _retire(self._clients.popitem(last=False)[1])
        else:
            self._clients.move_to_end(key)
        return client

    def reset_clients(self) -> None:
        """Forget cached clients (after sign-in/out). In-flight calls keep theirs."""
        old, self._clients = self._clients, OrderedDict()
        for c in old.values():
            _retire(c)


MAX_CLIENTS = 64
RETIRE_GRACE_SECONDS = 1800  # longer than any single tool call (max wait is 1800s)


def _retire(client: StrobesAPI) -> None:
    """Close a dropped client later, once calls still using it have finished."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.call_later(RETIRE_GRACE_SECONDS,
                    lambda: loop.create_task(client.aclose()) if not loop.is_closed() else None)
SESSION = Session()


def _http_request(ctx: Context | None) -> Any:
    """The HTTP request behind this tool call, or None over stdio / in-memory."""
    if ctx is None:
        return None
    try:
        return ctx.request_context.request
    except (AttributeError, ValueError, LookupError):
        return None


def _local_only(ctx: Context | None, what: str) -> None:
    """Refuse host-affecting operations to remote (HTTP) clients.

    Over HTTP the stored login belongs to the machine running the server, not to
    the caller — a remote client must not sign it in/out, switch it, or read files
    from its disk.
    """
    if os.getenv("STROBES_MCP_LOCAL_HTTP") and not os.getenv("STROBES_MCP_REQUIRE_HEADER_AUTH"):
        return
    if _http_request(ctx) is not None or os.getenv("STROBES_MCP_TRANSPORT", "stdio") != "stdio":
        raise ToolError(f"{what} is only available when the server runs locally over stdio. "
                        "Remote clients authenticate per request (Authorization: Bearer "
                        "<MasterKey>); sign the host in with `strobes-agents-mcp login`.")


def _env_only_profile() -> Profile:
    """Deployment defaults from env vars only (no stored login)."""
    from .config import _env, _env_base_url, _env_bool

    p = Profile(base_url=_env_base_url() or "",
                org_id=_env("STROBES_ORGANIZATION_ID", "STROBES_ORG_ID", "STROBES_AI_ORG_ID") or "",
                deployment=_env("STROBES_AI_DEPLOYMENT") or "",
                tenant_host=_env("STROBES_TENANT_HOST"))
    tls = _env_bool("STROBES_VERIFY_TLS")
    p.verify_tls = False if _env_bool("STROBES_INSECURE") else (True if tls is None else tls)
    return p


def _allowed_url(url: str, server: Profile) -> bool:
    """Which Strobes URLs a remote client may point this server at (anti-SSRF)."""
    from fnmatch import fnmatch
    from urllib.parse import urlparse

    u = urlparse(url if "://" in url else f"https://{url}")
    host = (u.hostname or "").lower()
    if not host:
        return False
    patterns = [x.strip().lower() for x in os.getenv(
        "STROBES_MCP_ALLOWED_URLS", "*.strobes.co,strobes.co").split(",") if x.strip()]
    if server.host:
        patterns.append(server.host.lower())
    if u.scheme != "https" and host != (server.host or "").lower():
        return False
    return any(fnmatch(host, pat) for pat in patterns)


def _request_profile(ctx: Context | None) -> Profile | None:
    """Credentials sent by a remote client as HTTP headers (streamable-http mode).

    Accepted: ``Authorization: Bearer <MasterKey>`` (or ``X-Strobes-Api-Key``),
    ``X-Strobes-Organization-Id`` and ``X-Strobes-Url``. Missing pieces fall back
    to the server's own configuration.
    """
    req = _http_request(ctx)
    headers = getattr(req, "headers", None)
    if not headers:
        return None
    key = headers.get("x-strobes-api-key")
    authz = headers.get("authorization") or ""
    if not key and authz.lower().startswith(("bearer ", "token ")):
        key = authz.split(None, 1)[1].strip()
    if not key:
        return None
    if os.getenv("STROBES_MCP_REQUIRE_HEADER_AUTH"):
        # never expose the host's stored login (URL/org) — only what the operator
        # configured for the deployment via env
        server = _env_only_profile()
    else:
        server = resolve_profile(SESSION.profile_override)
    url = (headers.get("x-strobes-url") or "").strip()
    if url:
        if not _allowed_url(url, server):
            raise AuthError(f"X-Strobes-Url {url!r} isn't an allowed Strobes URL for this "
                            "server (https and *.strobes.co by default; the operator can "
                            "extend STROBES_MCP_ALLOWED_URLS).")
        p = Profile(base_url=url, verify_tls=server.verify_tls)
    else:
        # single-tenant deployment: the operator configured the URL
        p = Profile(base_url=server.base_url, deployment=server.deployment,
                    verify_tls=server.verify_tls, tenant_host=server.tenant_host)
    p.name = "request"
    p.master_key = key
    p.org_id = headers.get("x-strobes-organization-id") or (server.org_id if not url else "")
    p.workspace_id = headers.get("x-strobes-workspace-id") or None
    p.source = "request"
    return p


def tool(annotations: ToolAnnotations, title: str | None = None):
    """Register an async tool; turn API failures into clean MCP tool errors."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                result = await fn(*args, **kwargs)
                if isinstance(result, dict):
                    # compact JSON text (the SDK default pretty-prints, ~30% more
                    # tokens) plus the same data as structuredContent
                    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"),
                                      default=str)
                    return CallToolResult(content=[TextContent(type="text", text=text)],
                                          structuredContent=result)
                return result
            except ToolError:
                raise
            except (StrobesError, ConfigError, auth.LoginError) as e:
                raise ToolError(str(e)) from e
            except httpx.HTTPError as e:
                raise ToolError(f"Network error talking to Strobes: {e}") from e

        return mcp.tool(annotations=annotations, title=title)(wrapper)

    return deco


mcp = FastMCP("strobes", instructions=INSTRUCTIONS, website_url="https://strobes.co")
mcp._mcp_server.version = __version__  # report our version, not the SDK's


# --------------------------------------------------------------------------
# sign-in & session
# --------------------------------------------------------------------------
async def _poll_login_forever(login: auth.DeviceLogin) -> None:
    await auth.wait_for_login(login)  # never raises; failures land in login.status
    if login.status == "approved":
        # use the profile just signed in to, even if it isn't the file's default
        SESSION.profile_override = login.profile
        SESSION.reset_clients()


@tool(WRITE, "Sign in to Strobes")
async def strobes_login(
    ctx: Context,
    url: Annotated[Optional[str], Field(
        description="Strobes URL, e.g. https://acme.strobes.co. Defaults to the URL you're "
                    "signed in to, else https://app.strobes.co (org is picked in the browser).")] = None,
    profile: Annotated[Optional[str], Field(
        description="Profile name to save the sign-in under (default: current profile).")] = None,
    web_url: Annotated[Optional[str], Field(
        description="Web app URL for the approval page if it differs from the API host "
                    "(local dev only, e.g. http://localhost:3000).")] = None,
    open_browser: Annotated[bool, Field(
        description="Open the sign-in page in the local browser.")] = True,
) -> dict[str, Any]:
    """Start a browser sign-in (device flow, like `strobes login`).

    Returns a link and a short code. Show both to the user and ask them to approve
    in the browser (they pick the organization and an optional default
    workspace), then call `strobes_login_status`. Credentials are saved to the
    profile store shared with the Strobes CLI.
    """
    _local_only(ctx, "Signing in")
    current = resolve_profile(profile or SESSION.profile_override)
    name = profile or current.name
    if SESSION.login_task and not SESSION.login_task.done():
        SESSION.login_task.cancel()
    fallback = current if current.base_url else resolve_profile(SESSION.profile_override)
    default_url = current.login_url or (fallback.web_url if fallback.base_url else None)
    login = await auth.start_login(url or default_url, profile=name,
                                   verify_tls=fallback.verify_tls, web_url=web_url,
                                   launch_browser=open_browser)
    SESSION.login = login
    SESSION.login_task = asyncio.create_task(_poll_login_forever(login))
    out = login.public()
    out["next_step"] = (
        f"Ask the user to open {login.verification_url}, check the code "
        f"{login.user_code} matches, pick the organization and click Authorize. "
        "Then call strobes_login_status.")
    return out


@tool(RO, "Check sign-in progress")
async def strobes_login_status(
    ctx: Context,
    wait_seconds: Annotated[int, Field(ge=0, le=300, description=(
        "Wait up to this long for the user to finish approving."))] = 60,
) -> dict[str, Any]:
    """Status of the browser sign-in started by `strobes_login`
    (pending / approved / denied / expired)."""
    _local_only(ctx, "Sign-in status")
    login = SESSION.login
    if login is None:
        p = SESSION.profile(ctx)
        return {"status": "signed_in" if p.complete else "not_started",
                **({"profile": p.name, "email": p.email} if p.complete else {})}
    deadline = time.monotonic() + wait_seconds
    while login.status == "pending" and time.monotonic() < deadline:
        left = int(deadline - time.monotonic())
        await ctx.report_progress(wait_seconds - left, wait_seconds,
                                  f"Waiting for approval (code {login.user_code})")
        await asyncio.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
    out = login.public()
    if login.status == "pending":
        out["next_step"] = "Still waiting for the user — call strobes_login_status again."
    elif login.status == "approved":
        out["next_step"] = "Signed in. Call strobes_whoami or list_findings."
    return out


@tool(RO, "Who am I / connection status")
async def strobes_whoami(ctx: Context) -> dict[str, Any]:
    """Show the active Strobes connection (URL, organization, user) and verify it
    works. Call this first."""
    p = SESSION.profile(ctx)
    remote = p.source == "request" or _http_request(ctx) is not None
    out: dict[str, Any] = {"server_version": __version__, **p.redacted()}
    if remote:
        out.pop("profile", None)
    if not p.complete:
        out.update(signed_in=False, next_step=NOT_SIGNED_IN)
        if not remote:
            out["profiles"] = list_profiles()
        return render.compact(out)
    api = SESSION.api(ctx)
    try:
        data = await api.graphql(Q.ASSETS, {"org": p.org_id, "size": 1}, op="allAssets")
        out.update(signed_in=True, connected=True,
                   has_assets=bool((data.get("allAssets") or {}).get("objects")))
    except AuthError as e:
        out.update(signed_in=False, connected=False, error=str(e))
    profiles = [] if remote else list_profiles()
    if len(profiles) > 1:
        out["profiles"] = profiles
    return render.compact(out)


@tool(WRITE_IDEMPOTENT, "Switch Strobes profile")
async def strobes_use_profile(
    ctx: Context,
    profile: Annotated[str, Field(description="Profile name (see strobes_whoami → profiles).")],
    persist: Annotated[bool, Field(description="Also make it the default for the CLI and "
                                               "future sessions.")] = False,
) -> dict[str, Any]:
    """Switch to another signed-in Strobes organization/profile."""
    _local_only(ctx, "Switching profiles")
    names = {p["profile"] for p in list_profiles()}
    if profile not in names:
        raise ToolError(f"No profile named {profile!r}. Known: {', '.join(sorted(names)) or 'none'}. "
                        "Use strobes_login with profile=... to add one.")
    if persist:
        set_current_profile(profile)
    SESSION.profile_override = profile
    return resolve_profile(profile).redacted()


@tool(DESTRUCTIVE, "Sign out of Strobes")
async def strobes_logout(
    ctx: Context,
    profile: Annotated[Optional[str], Field(description="Profile to sign out (default: current).")] = None,
) -> dict[str, Any]:
    """Forget the stored API key for a profile (also signs the Strobes CLI out of it).
    The key itself stays valid on the server; revoke it in Settings → API access."""
    _local_only(ctx, "Signing out")
    name = profile or resolve_profile(SESSION.profile_override).name
    removed = clear_login(name)
    SESSION.reset_clients()
    return {"profile": name, "signed_out": removed}




# --------------------------------------------------------------------------
# reference data (from the Strobes models; codes are what the API takes/returns)
# --------------------------------------------------------------------------
SEVERITY = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
FINDING_STATE = {0: "new", 1: "active", 2: "resolved", 3: "duplicate", 4: "not_applicable",
                 5: "committed", 6: "accepted_risk", 7: "wont_fix"}
FINDING_LEVEL = {1: "code", 2: "web", 3: "mobile", 4: "network", 5: "cloud", 6: "package"}
ASSET_TYPE = {0: "unknown", 1: "web", 2: "mobile", 3: "network", 4: "cloud", 5: "website",
              6: "api_service", 7: "code_repo", 8: "web_server", 9: "db_server",
              10: "container", 11: "container_image", 12: "firewall", 13: "router",
              14: "switch", 15: "network_hub", 16: "printer", 17: "generic_server",
              18: "wireless_access_point", 19: "mail_server", 20: "dns_server",
              21: "dhcp_server", 22: "endpoint", 23: "network_storage", 24: "vm"}
SENSITIVITY = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}
EXPOSURE = {1: "high", 2: "medium", 3: "low"}
ENGAGEMENT_STATE = {1: "new", 2: "in_progress", 4: "completed", 5: "retest_requested",
                    6: "finished", 7: "on_hold"}

SeverityName = Literal["info", "low", "medium", "high", "critical"]
StateName = Literal["new", "active", "resolved", "duplicate", "not_applicable", "committed",
                    "accepted_risk", "wont_fix"]
LevelName = Literal["code", "web", "mobile", "network", "cloud", "package"]
_rev = lambda d: {v: k for k, v in d.items()}  # noqa: E731


def _label(table: dict[int, str], code: Any) -> Any:
    try:
        return table.get(int(code), code)
    except (TypeError, ValueError):
        return code


def _and(*parts: str | None) -> str | None:
    parts = [p.strip() for p in parts if p and p.strip()]
    if not parts:
        return None
    return " and ".join(f"({p})" if " or " in p.lower() else p for p in parts)


def _in(field: str, codes: list[int]) -> str:
    return f"{field} = {codes[0]}" if len(codes) == 1 else f"{field} in ({', '.join(map(str, codes))})"


def _asset(a: dict[str, Any] | None) -> dict[str, Any]:
    if not a:
        return {}
    out = {k: v for k, v in render.snake_keys(a).items()}
    out["type"] = _label(ASSET_TYPE, a.get("type"))
    if "sensitivity" in a:
        out["sensitivity"] = _label(SENSITIVITY, a.get("sensitivity"))
    if "exposed" in a:
        out["exposure"] = _label(EXPOSURE, out.pop("exposed", None))
    if isinstance(a.get("tags"), list):
        out["tags"] = [t.get("name") for t in a["tags"] if isinstance(t, dict)]
    return render.compact(out)


def _finding(b: dict[str, Any] | None) -> dict[str, Any]:
    if not b:
        return {}
    out = render.snake_keys(b)
    out["severity"] = _label(SEVERITY, b.get("severity"))
    out["state"] = _label(FINDING_STATE, b.get("state"))
    out["level"] = _label(FINDING_LEVEL, out.pop("bug_level", None))
    if isinstance(b.get("bugTags"), list):
        out["tags"] = [t.get("name") for t in b["bugTags"] if isinstance(t, dict)]
        out.pop("bug_tags", None)
    if isinstance(out.get("cve"), list):
        out["cve"] = [c.get("cve_id") for c in out["cve"] if isinstance(c, dict)] or None
    if isinstance(out.get("cwe"), list):
        out["cwe"] = [f"CWE-{c.get('cwe_id')}: {c.get('type')}" for c in out["cwe"]
                      if isinstance(c, dict)] or None
    for k in ("description", "mitigation", "steps_to_reproduce", "evidence"):
        if isinstance(out.get(k), str):
            out[k] = render.truncate(out[k], 6000)
    return render.compact(out)


def _user_name(u: Any) -> str | None:
    if not isinstance(u, dict):
        return None
    return u.get("email") or " ".join(filter(None, [u.get("firstName"), u.get("lastName")])) or None


def _engagement(e: dict[str, Any] | None) -> dict[str, Any]:
    if not e:
        return {}
    out = render.snake_keys(e)
    out["state"] = _label(ENGAGEMENT_STATE, e.get("state"))
    assignees = e.get("assignees")
    if isinstance(assignees, list):
        out["assigned_to"] = [_user_name(u) for u in assignees if _user_name(u)]
    out["created_by"] = _user_name(e.get("createdBy"))
    return render.compact(out)


def _comment(c: dict[str, Any] | None) -> dict[str, Any]:
    if not c:
        return {}
    out = render.snake_keys(c)
    by = out.pop("commented_by", None) or {}
    out["by"] = by.get("email") or " ".join(filter(None, [by.get("first_name"),
                                                          by.get("last_name")])) or None
    return render.compact(out)


@tool(RO, "Strobes reference codes")
async def strobes_reference() -> dict[str, Any]:
    """Numeric codes Strobes uses in queries and filters: severities, finding states
    and levels, asset types / sensitivity / exposure, engagement states, plus query
    language examples. No API call."""
    return {
        "finding_severity": SEVERITY, "finding_state": FINDING_STATE,
        "finding_level": FINDING_LEVEL, "asset_type": ASSET_TYPE,
        "asset_sensitivity": SENSITIVITY, "asset_exposure": EXPOSURE,
        "engagement_state": ENGAGEMENT_STATE,
        "query_examples": [
            'severity >= 4 and state in (0, 1)        # open high/critical',
            'cvss >= 7 and exploit_available = "true"',
            'title ~ "sql"                            # contains (no `like`)',
            'asset.id = 12   /   asset.name ~ "payments"',
            'finding_tags = "pci"   /   asset_tags = "prod"',
            'due_date < "2027-01-01"',
            'id in (101, 102)                         # exact set, for update_findings',
            'type = 1 and exposed = 1                 # internet-facing web assets',
            'sensitivity >= 3   /   risk_score >= 70'],
        "syntax": ("DjangoQL: = != > >= < <=, ~ (contains), !~, in (...), and/or, quoted "
                   "strings/dates, yes/no flags are strings (\"true\"), relations via dots."),
    }


# --------------------------------------------------------------------------
# assets
# --------------------------------------------------------------------------
@tool(RO, "List assets")
async def list_assets(
    ctx: Context,
    search_query: SearchQuery = None,
    type: Annotated[Optional[list[int]], Field(description=(
        "Asset type codes (1=web, 2=mobile, 3=network, 4=cloud, 7=code repo; see "
        "strobes_reference)."))] = None,
    order_by: Annotated[Optional[list[str]], Field(description=(
        "Sort fields, '-' for descending, e.g. ['-risk_score'].")) ] = None,
    page: Page = 1,
    page_size: PageSize = 25,
) -> dict[str, Any]:
    """List / search assets (applications, hosts, cloud resources, repos …)."""
    api = SESSION.api(ctx)
    q = _and(search_query, _in("type", type) if type else None)
    node = (await api.graphql(Q.ASSETS, {"org": api.profile.org_id, "q": q, "page": page,
                                         "size": page_size, "order": order_by},
                              op="allAssets"))["allAssets"] or {}
    rows = [_asset(a) for a in node.get("objects") or []]
    out: dict[str, Any] = {"assets": rows, "count": len(rows), "page": page}
    if node.get("hasNext"):
        out["next_page"] = page + 1
    return out


@tool(RO, "Get an asset")
async def get_asset(
    ctx: Context,
    asset_id: Annotated[int, Field(description="Numeric asset id.")],
) -> dict[str, Any]:
    """Full detail for one asset."""
    api = SESSION.api(ctx)
    objs = (await api.graphql(Q.ASSET_GET, {"org": api.profile.org_id, "q": f"id = {int(asset_id)}"},
                              op="allAssets"))["allAssets"]["objects"] or []
    if not objs:
        raise ToolError(f"No asset with id {asset_id}.")
    out = _asset(objs[0])
    out["web_url"] = api.profile.app_url(f"assets/{asset_id}")
    return out


@tool(WRITE, "Create an asset")
async def create_asset(
    ctx: Context,
    name: Annotated[str, Field(description="Asset name.")],
    type: Annotated[int, Field(description="Asset type code: 1=web, 2=mobile, 3=network, "
                                           "4=cloud, 7=code repo (see strobes_reference).")],
    url: Annotated[Optional[str], Field(description="URL (web / code assets).")] = None,
    hostname: Annotated[Optional[str], Field(description="Hostname (network assets).")] = None,
    ipaddress: Annotated[Optional[str], Field(description="IP address (network assets).")] = None,
    sensitivity: Annotated[int, Field(ge=0, le=4, description=(
        "Business sensitivity: 0=none, 1=low, 2=medium, 3=high, 4=critical."))] = 2,
    exposure: Annotated[int, Field(ge=1, le=3, description=(
        "Exposure: 1=high (internet-facing), 2=medium, 3=low."))] = 2,
    tags: Annotated[Optional[list[str]], Field(description="Tag names.")] = None,
    cloud_type: Annotated[Optional[int], Field(description="Cloud provider type code.")] = None,
) -> dict[str, Any]:
    """Create an asset in the organization."""
    api = SESSION.api(ctx)
    p = (await api.graphql(Q.CREATE_ASSET, {
        "org": api.profile.org_id, "name": name, "type": type, "url": url,
        "hostname": hostname, "ip": ipaddress, "sensitivity": sensitivity,
        "exposed": exposure, "tags": tags, "cloudType": cloud_type},
        op="createAsset"))["createAsset"] or {}
    return {"created": _asset(p.get("asset"))}


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------
def _finding_query(search_query: str | None, severity: list[str] | None,
                   state: list[str] | None, open_only: bool) -> str | None:
    sev = _in("severity", [_rev(SEVERITY)[s] for s in severity]) if severity else None
    if state:
        st = _in("state", [_rev(FINDING_STATE)[s] for s in state])
    elif open_only:
        st = "state in (0, 1)"
    else:
        st = None
    return _and(search_query, sev, st)


@tool(RO, "List findings")
async def list_findings(
    ctx: Context,
    search_query: SearchQuery = None,
    severity: Annotated[Optional[list[SeverityName]], Field(description="Only these severities.")] = None,
    state: Annotated[Optional[list[StateName]], Field(description="Only these states.")] = None,
    open_only: Annotated[bool, Field(description=(
        "Only new/active findings (ignored when `state` is given)."))] = False,
    order_by: Annotated[Optional[list[str]], Field(description=(
        "Sort fields, '-' for descending, e.g. ['-severity', '-cvss'].")) ] = None,
    page: Page = 1,
    page_size: PageSize = 25,
) -> dict[str, Any]:
    """List / search findings (vulnerabilities, misconfigurations …) across the
    organization. Use get_finding for description, evidence and remediation."""
    api = SESSION.api(ctx)
    q = _finding_query(search_query, severity, state, open_only)
    node = (await api.graphql(Q.BUGS, {"org": api.profile.org_id, "q": q, "page": page,
                                       "size": page_size, "order": order_by},
                              op="allBugs"))["allBugs"] or {}
    rows = [_finding(b) for b in node.get("objects") or []]
    out: dict[str, Any] = {"findings": rows, "count": len(rows), "page": page}
    if q:
        out["query"] = q
    if node.get("hasNext"):
        out["next_page"] = page + 1
    return out


@tool(RO, "Get a finding")
async def get_finding(
    ctx: Context,
    finding_id: Annotated[int, Field(description="Numeric finding id.")],
) -> dict[str, Any]:
    """Full detail for one finding: description, steps to reproduce, evidence,
    mitigation, CVE/CWE, scores, asset and engagements."""
    api = SESSION.api(ctx)
    objs = (await api.graphql(Q.BUG_GET, {"org": api.profile.org_id, "q": f"id = {int(finding_id)}"},
                              op="allBugs"))["allBugs"]["objects"] or []
    if not objs:
        raise ToolError(f"No finding with id {finding_id}.")
    out = _finding(objs[0])
    out["web_url"] = api.profile.app_url(f"findings/{finding_id}")
    return out


LEVEL_FIELD = {1: "code", 2: "web", 3: "mobile", 4: "network", 5: "cloud", 6: "package"}


@tool(WRITE, "Create a finding")
async def create_finding(
    ctx: Context,
    title: Annotated[str, Field(description="Finding title.")],
    description: Annotated[str, Field(description="What the issue is (markdown).")],
    level: Annotated[LevelName, Field(description="Finding level (category).")],
    asset_ids: Annotated[list[int], Field(min_length=1, description=(
        "Asset id(s) the finding affects (see list_assets)."))],
    severity: Annotated[Optional[SeverityName], Field(description="Severity.")] = None,
    mitigation: Annotated[Optional[str], Field(description="How to fix it.")] = None,
    steps_to_reproduce: Annotated[Optional[str], Field()] = None,
    evidence: Annotated[Optional[str], Field()] = None,
    cve: Annotated[Optional[list[str]], Field(description="e.g. ['CVE-2021-44228'].")] = None,
    cwe: Annotated[Optional[list[int]], Field(description="e.g. [79].")] = None,
    cvss_v3: Annotated[Optional[float], Field(ge=0, le=10)] = None,
    tags: Annotated[Optional[list[str]], Field()] = None,
    engagement_id: Annotated[Optional[str], Field(description="Attach to an engagement (UUID).")] = None,
    details: Annotated[Optional[dict[str, Any]], Field(description=(
        "Level-specific details. Web findings need {\"affected_endpoints\": "
        "[\"https://host/path\"]} (plus optional request/response)."))] = None,
) -> dict[str, Any]:
    """Report a new finding against one or more assets."""
    lvl = _rev(FINDING_LEVEL)[level]
    if lvl == 2 and not (details or {}).get("affected_endpoints"):
        raise ToolError("Web findings need details={'affected_endpoints': ['https://host/path']}.")
    api = SESSION.api(ctx)
    variables: dict[str, Any] = {
        "org": api.profile.org_id, "title": title, "description": description, "level": lvl,
        "severity": _rev(SEVERITY)[severity] if severity else None, "assets": asset_ids,
        "mitigation": mitigation, "steps": steps_to_reproduce, "evidence": evidence,
        "cves": cve, "cwes": cwe, "tags": tags, "engagement": engagement_id,
        "cvssV3": cvss_v3}
    if lvl == 2:
        # Web.request / Web.response are non-null text columns the serializer requires
        details = {"request": "", "response": "", **(details or {})}
    if details is not None:
        variables[LEVEL_FIELD[lvl]] = json.dumps(details)
    p = (await api.graphql(Q.BUG_CREATE, variables, op="bugCreate"))["bugCreate"] or {}
    return {"created": _finding(p.get("bug"))}


MAX_BULK = 200


@tool(DESTRUCTIVE, "Update findings (state / severity)")
async def update_findings(
    ctx: Context,
    search_query: Annotated[str, Field(description=(
        "Which findings to change, ideally an exact set: 'id = 42', 'id in (1, 2, 3)'. "
        "Every match is updated — check it with list_findings first."))],
    state: Annotated[Optional[StateName], Field(description="New state.")] = None,
    severity: Annotated[Optional[SeverityName], Field(description="New severity.")] = None,
    allow_many: Annotated[bool, Field(description=(
        f"Required when the query matches more than {MAX_BULK} findings."))] = False,
    confirm_seconds: Annotated[int, Field(ge=0, le=60, description=(
        "Strobes applies bulk updates in the background; re-check for up to this long "
        "and report which findings actually changed."))] = 10,
) -> dict[str, Any]:
    """Change the state (e.g. resolved, accepted_risk, not_applicable) and/or
    severity of every finding matching `search_query`."""
    if state is None and severity is None:
        raise ToolError("Give at least one of `state` or `severity`.")
    if not search_query.strip():
        raise ToolError("search_query must not be empty (it would match every finding).")
    api = SESSION.api(ctx)
    org = api.profile.org_id
    probe = (await api.graphql(Q.BUG_IDS, {"org": org, "q": search_query, "size": MAX_BULK},
                               op="allBugs"))["allBugs"] or {}
    matched = len(probe.get("objects") or [])
    if matched == 0:
        raise ToolError(f"No findings match {search_query!r}; nothing changed.")
    if probe.get("hasNext") and not allow_many:
        raise ToolError(f"{search_query!r} matches more than {MAX_BULK} findings. Narrow it, "
                        "or pass allow_many=true after confirming with the user.")
    want_state = _rev(FINDING_STATE)[state] if state else None
    want_sev = _rev(SEVERITY)[severity] if severity else None
    p = (await api.graphql(Q.BUG_BULK_UPDATE, {
        "org": org, "q": search_query, "state": want_state, "severity": want_sev},
        op="bugBulkUpdate"))["bugBulkUpdate"] or {}
    ids = [int(b["id"]) for b in p.get("bugs") or [] if b.get("id")]
    out: dict[str, Any] = {"submitted": len(ids)}

    def done(b: dict[str, Any]) -> bool:
        return ((want_state is None or b.get("state") == want_state)
                and (want_sev is None or b.get("severity") == want_sev))

    current: list[dict[str, Any]] = []
    deadline = time.monotonic() + confirm_seconds
    probe_ids = ids[:MAX_BULK]
    while probe_ids:
        q = f"id in ({', '.join(map(str, probe_ids))})"
        current = (await api.graphql(Q.BUGS, {"org": org, "q": q, "page": 1,
                                              "size": len(probe_ids)},
                                     op="allBugs"))["allBugs"]["objects"] or []
        if all(done(b) for b in current) or time.monotonic() >= deadline:
            break
        await _sleep(2)
    applied = [b for b in current if done(b)]
    pending = [b for b in current if not done(b)]
    out["applied"] = len(applied)
    if pending:
        out["pending"] = [_finding(b) for b in pending[:50]]
        out["note"] = ("Not applied yet. Strobes runs bulk updates in the background — check "
                       "again shortly with list_findings. If they never change, your org may "
                       "require approval for state changes (an approval request was created "
                       "for an approver), or the server's background workers aren't running.")
    else:
        out["updated"] = [_finding(b) for b in applied[:50]]
    if len(ids) > 50:
        out["truncated"] = True
    return out


@tool(WRITE, "Comment on a finding")
async def add_finding_comment(
    ctx: Context,
    finding_id: Annotated[int, Field(description="Numeric finding id.")],
    comment: Annotated[str, Field(description="Comment text (markdown).")],
    internal: Annotated[bool, Field(description=(
        "Internal-only note (honoured for org owners/managers)."))] = False,
) -> dict[str, Any]:
    """Add a comment to a finding."""
    api = SESSION.api(ctx)
    p = (await api.graphql(Q.ADD_BUG_COMMENT, {"org": api.profile.org_id, "bug": int(finding_id),
                                              "comment": comment, "internal": internal},
                           op="addBugComment"))["addBugComment"] or {}
    return {"comment": _comment(p.get("comment"))}


@tool(RO, "List comments")
async def list_comments(
    ctx: Context,
    finding_id: Annotated[Optional[int], Field(description="Comments on this finding.")] = None,
    engagement_id: Annotated[Optional[str], Field(description="Comments on this engagement.")] = None,
    page: Page = 1,
    page_size: PageSize = 25,
) -> dict[str, Any]:
    """Comments on a finding or an engagement."""
    if (finding_id is None) == (engagement_id is None):
        raise ToolError("Give exactly one of finding_id or engagement_id.")
    api = SESSION.api(ctx)
    node = (await api.graphql(Q.COMMENTS, {"org": api.profile.org_id, "bug": finding_id,
                                           "eng": engagement_id, "page": page,
                                           "size": page_size},
                              op="allComments"))["allComments"] or {}
    rows = [_comment(c) for c in node.get("objects") or []]
    out: dict[str, Any] = {"comments": rows, "total": node.get("totalCount")}
    if node.get("hasNext"):
        out["next_page"] = page + 1
    return out


# --------------------------------------------------------------------------
# engagements
# --------------------------------------------------------------------------
@tool(RO, "List engagements")
async def list_engagements(
    ctx: Context,
    search_query: SearchQuery = None,
    order_by: Annotated[Optional[list[str]], Field(description="e.g. ['-created'].")] = None,
    page: Page = 1,
    page_size: PageSize = 25,
) -> dict[str, Any]:
    """List engagements (pentests, assessments, AI pentests)."""
    api = SESSION.api(ctx)
    node = (await api.graphql(Q.ENGAGEMENTS, {"org": api.profile.org_id, "q": search_query,
                                              "page": page, "size": page_size,
                                              "order": order_by},
                              op="allEngagements"))["allEngagements"] or {}
    rows = [_engagement(e) for e in node.get("objects") or []]
    out: dict[str, Any] = {"engagements": rows, "count": len(rows), "total": node.get("totalCount"),
                           "page": page}
    if node.get("hasNext"):
        out["next_page"] = page + 1
    return out


@tool(WRITE, "Create an engagement")
async def create_engagement(
    ctx: Context,
    name: Annotated[str, Field(description="Engagement name.")],
    scheduled_date: Annotated[str, Field(description="Start date, YYYY-MM-DD.")],
    delivery_date: Annotated[str, Field(description="Delivery date, YYYY-MM-DD.")],
    subscribed_services: Annotated[list[str], Field(min_length=1, description=(
        "Services in scope, e.g. ['agentic:web-app']."))],
    is_self_managed: Annotated[bool, Field(description="Self-managed (no vendor).")] = True,
    assessment_data: Annotated[Optional[dict[str, Any]], Field(description=(
        "Per-service scope (assets / search queries), as in the web app."))] = None,
    executive_summary: Annotated[Optional[str], Field()] = None,
    plans: Annotated[int, Field(ge=1)] = 1,
) -> dict[str, Any]:
    """Create an engagement (security assessment)."""
    api = SESSION.api(ctx)
    p = (await api.graphql(Q.CREATE_ENGAGEMENT, {
        "org": api.profile.org_id, "name": name, "scheduled": scheduled_date,
        "delivery": delivery_date, "services": subscribed_services, "plans": plans,
        "selfManaged": is_self_managed,
        "assessment": json.dumps(assessment_data) if assessment_data is not None else None,
        "summary": executive_summary, "fields": "{}", "documents": []},
        op="createEngagement"))["createEngagement"] or {}
    return {"created": _engagement(p.get("engagement"))}


EngagementStateName = Literal["new", "in_progress", "completed", "retest_requested", "finished", "on_hold"]


@tool(WRITE, "Update engagement state")
async def update_engagement(
    ctx: Context,
    engagement_id: Annotated[str, Field(description="Engagement UUID.")],
    state: Annotated[EngagementStateName, Field(description="New state.")],
) -> dict[str, Any]:
    """Change an engagement's state (e.g. in_progress, completed, finished, on_hold)."""
    api = SESSION.api(ctx)
    variables: dict[str, Any] = {
        "org": api.profile.org_id,
        "id": engagement_id,
        "state": _rev(ENGAGEMENT_STATE)[state],
    }
    p = (await api.graphql(Q.UPDATE_ENGAGEMENT, variables,
                           op="updateEngagement"))["updateEngagement"] or {}
    return {"updated": _engagement(p.get("engagement"))}


@tool(WRITE, "Comment on an engagement")
async def add_engagement_comment(
    ctx: Context,
    engagement_id: Annotated[str, Field(description="Engagement UUID.")],
    comment: Annotated[str, Field(description="Comment text (markdown).")],
) -> dict[str, Any]:
    """Add a comment to an engagement."""
    api = SESSION.api(ctx)
    p = (await api.graphql(Q.ADD_ENGAGEMENT_COMMENT, {"org": api.profile.org_id,
                                                     "eng": engagement_id, "comment": comment},
                           op="addEngagementComment"))["addEngagementComment"] or {}
    return {"comment": _comment(p.get("comment"))}


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------
@mcp.prompt(title="Triage open findings")
def triage_findings(scope: str = "critical and high severity") -> str:
    """Walk through open findings and propose triage decisions."""
    return (
        f"Triage the open Strobes findings ({scope}).\n"
        "1. strobes_whoami (sign in with strobes_login if needed).\n"
        "2. list_findings(open_only=true, severity=[...], order_by=['-severity','-cvss']); "
        "narrow with search_query, e.g. 'exploit_available = \"true\"'.\n"
        "3. For the top items, get_finding and judge exploitability, exposure and fix.\n"
        "4. Propose per finding: keep / resolved / accepted_risk / not_applicable / duplicate, "
        "with a one-line reason. Do NOT call update_findings until I approve the list.")


@mcp.prompt(title="Asset risk summary")
def asset_risk_summary(asset: str) -> str:
    """Risk brief for one asset."""
    return (
        f"Give me a risk summary for the Strobes asset '{asset}': find it with list_assets "
        "(search_query 'name ~ \"<name>\"', or get_asset if it's an id), then list_findings "
        "with search_query 'asset.id = <id>' and open_only=true. Summarize exposure, the worst "
        "open issues with severity and fix, and what to do first.")


def build(transport: str = "stdio") -> FastMCP:
    os.environ["STROBES_MCP_TRANSPORT"] = transport
    return mcp
