---
name: strobes
description: Manage Strobes assets, findings (vulnerabilities) and engagements via the Strobes MCP server. Use when the user wants to list, search, create or update assets, security findings/vulnerabilities, or engagements/assessments in Strobes, or add comments to them. Triggers on "in Strobes", "my assets", "my findings", "create a vulnerability", "list critical findings", "new engagement/assessment".
---

# Strobes (assets, findings, engagements)

This skill drives the `strobes` MCP server, which wraps the Strobes **public**
GraphQL API (MasterKey auth). Use it to manage three object types:

- **Assets** — the things you protect (web apps, mobile apps, network hosts,
  cloud accounts, code repos).
- **Findings** (a.k.a. bugs / vulnerabilities) — security issues on assets.
- **Engagements** — security assessments / pentests scoped to assets.

## First call
Always start with `strobes_whoami` to confirm the server is configured
(host + organization) and reachable. It also returns the enum reference
(asset types, bug levels, severities, finding states).

## Enums (memorise these)
- **Asset type**: 1=Web, 2=Mobile, 3=Network, 4=Cloud, 7=Code repository.
- **Bug level** (finding category): 1=Code, 2=Web, 3=Mobile, 4=Network, 5=Cloud, 6=Package.
- **Severity**: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical.
- **Finding state**: 1=Open, 2=Closed/Fixed, 3=False Positive, 4=Accepted Risk, 5=Duplicate, 6=Out of Scope.
- **Sensitivity**: 1..4 (4=Critical). **Exposed**: 1=Public, 2=Internal.

## Searching
`list_assets`, `list_findings` and `list_engagements` take a `search_query`
string in the Strobes query language. See `references/query-language.md` for
the full operator/field list. Common filters:
- Critical open findings: `list_findings(search_query="severity = 5 and state = 1")`
- Web assets: `list_assets(search_query="type = 1")`
- Findings with a public exploit: `list_findings(search_query="exploit_available = true")`

## Creating a finding
`create_finding` requires `title`, `description`, `bug_level`, and at least one
asset via `asset_id` (or `asset_ids`). For **web** findings (bug_level=2) you
MUST pass `details` with a non-empty `affected_endpoints`, e.g.:
`details={"affected_endpoints": ["https://host/login"], "request": "...", "response": "..."}`.
Set `severity` explicitly; attach to an engagement with `engagement_id`.

## Updating findings
`update_findings` is a bulk operation keyed by `search_query`. To change one
finding: `update_findings(search_query="id = 42", state=2)` (mark fixed).
Marking false-positive: `state=3`. Accepting risk: `state=4`.

## Comments
`add_finding_comment(bug_id, comment, internal=False)` and
`add_engagement_comment(engagement_id, comment)`. `internal=True` is only
honoured for org owners/managers.

## Guidance
- IDs: assets and findings use **numeric** ids; engagements use **UUIDs**.
- Prefer narrow `search_query` filters and small `page_size` — the org may have
  thousands of records.
- Tools return a structured `{"error": "..."}` on failure; read it and adjust
  (e.g. a missing required field) rather than retrying blindly.
- This server is scoped to one organization (set at config time); you cannot
  switch orgs at call time.
