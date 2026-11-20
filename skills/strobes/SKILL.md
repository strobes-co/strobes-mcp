---
name: strobes
description: Search, triage and manage Strobes assets, findings (vulnerabilities) and engagements through the strobes MCP server. Use when the user asks about their security findings or exposure in Strobes — "show my critical findings", "what's exploitable on prod", "triage these vulns", "mark 42 as resolved / accepted risk", "which assets are internet-facing", "create a finding/asset/engagement", "comment on this finding", "sign in to Strobes".
---

# Strobes (assets, findings, engagements)

Tools come from the `strobes` MCP server (Strobes public API). For AI agents and
workspaces, use the companion `strobes-agents` server.

## Sign-in (no API key to paste)
`strobes_whoami` first. If `signed_in` is false: `strobes_login(url?)` → show the user the
`verification_url` (clickable) and `user_code`; they confirm the code, pick the organization
and click Authorize → `strobes_login_status(wait_seconds=120)` until `approved`. The login is
shared with the Strobes CLI; `strobes_use_profile` switches organizations.

## Finding things
Prefer the typed filters over hand-written codes:
- `list_findings(open_only=true, severity=["critical","high"], order_by=["-cvss"])`
- `list_assets(type=[1], order_by=["-risk_score"])`
- `list_engagements(search_query='state = 2')`

Add a DjangoQL `search_query` for anything else (see `references/query-language.md`):
`exploit_available = "true"`, `title ~ "sql"` (contains), `asset.id = 12`,
`asset_tags = "prod"`, `finding_tags = "pci"`, `due_date < "2027-01-01"`.
Strings are quoted, yes/no flags are strings, relations use dots, there is no `like`.

`get_finding(id)` has the description, evidence, steps, mitigation, CVE/CWE and a web link;
`get_asset(id)` the asset detail; `strobes_reference` every code table.

## Codes that matter
- Severity: 1 info, 2 low, 3 medium, 4 high, 5 critical.
- Finding state: 0 new, 1 active, 2 resolved, 3 duplicate, 4 not applicable,
  5 committed, 6 accepted risk, 7 won't fix. Open = new or active.
- Asset exposure: 1 high (internet-facing), 2 medium, 3 low. Sensitivity 0–4.
Tools take and return names (`"accepted_risk"`, `"critical"`), not numbers.

## Changing things
- `update_findings(search_query, state=..., severity=...)` changes **every** match. Use an
  exact set (`id in (1, 2, 3)`), confirm the list with the user first, never an open-ended
  query. It refuses empty matches and >200 matches unless `allow_many=true`.
  Strobes applies the change in the background: report `applied` vs `pending` honestly. Pending
  items may need an approver if the org requires approval for state changes.
- `create_finding(title, description, level, asset_ids, severity, ...)` — web findings need
  `details={"affected_endpoints": ["https://host/path"]}` (request/response optional).
- `create_asset(name, type, url|hostname|ipaddress, sensitivity, exposure, tags)`.
- `create_engagement(...)`, `add_finding_comment`, `add_engagement_comment`, `list_comments`.

## Guidance
- Asset and finding ids are numbers; engagement ids are UUIDs.
- Keep pages small (`page_size` ≤ 25) and follow `next_page`; orgs often have thousands of
  findings.
- Errors are tool errors with a next step (sign in again, fix a field) — follow them.
