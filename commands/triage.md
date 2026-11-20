---
description: Triage open Strobes findings and propose decisions
argument-hint: "[scope, e.g. 'critical on production web apps']"
---
Triage open Strobes findings — scope: ${ARGUMENTS:-critical and high severity}.

- `strobes_whoami` first (run /strobes-mcp:login if not signed in).
- `list_findings(open_only=true, severity=[...], order_by=['-severity','-cvss'])`; refine with
  `search_query` (e.g. `exploit_available = true`, `asset_id = 12`).
- `get_finding` on the top items; judge exploitability, exposure and the fix.
- Give me a table: id, title, severity, asset, proposed decision (keep / resolved /
  accepted_risk / not_applicable / duplicate) and a one-line reason.
- Do NOT call `update_findings` until I approve; then update with an exact `id in (...)` query.
