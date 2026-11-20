# Changelog

## 0.2.0
- **Browser sign-in** (`strobes-mcp login` / `strobes_login` tool), the same device flow as
  `strobes login`. Credentials are shared with the Strobes CLI and strobes-agents-mcp. Env vars
  still work and are never mixed field-by-field with a stored login. Multi-org profiles.
- **One-command setup** for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and
  Gemini CLI (`setup`, `install <client>`). The plugin needs no env vars and adds
  `/strobes-mcp:login`, `:triage`, `:posture`.
- **Correct reference codes.** The old docs mapped finding state 3 to "False positive",
  4 to "Accepted risk" and 6 to "Out of scope", but the backend uses 3=duplicate,
  4=not applicable, 6=accepted risk (so "mark false positive" marked findings Duplicate).
  Exposure is 1=high/2=medium/3=low, not public/internal. Tools now take names
  (`state="accepted_risk"`).
- **Working query examples.** The query docs now use valid DjangoQL: `~` instead of `like`,
  quoted yes/no flags, `asset.id`, `asset_tags` / `finding_tags`. Every example is checked
  against the API.
- New: `get_finding` (full detail + web link), `strobes_reference`, typed filters
  (`open_only`, `severity`, `state`, `type`, `order_by`), prompts.
- `update_findings`: checks the match first, refuses empty or >200-match updates unless allowed,
  and reports applied vs pending (bulk updates are asynchronous in Strobes). Dropped `due_date`,
  which the API never accepted.
- `create_asset` works with just name + type (sensitivity and exposure default to medium; the API
  required both). `create_finding` fills the request/response fields web findings require.
- Any GraphQL error now fails the call, instead of partial data reading as "no results".
- MCP best practices: annotations and titles on every tool, instructions, real tool errors,
  compact JSON.
- Streamable HTTP with per-request header auth, a URL allowlist, `--allowed-host` and
  local-only session tools. Dockerfile, CI across Python 3.10–3.13, release workflow, MCP
  Registry `server.json`.
- Depends only on `mcp` + `httpx` (dropped the git-branch `strobes-graphql-client`).
