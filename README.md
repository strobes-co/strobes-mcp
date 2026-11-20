# strobes-mcp

MCP server for **Strobes**. It lets Claude Code, Cursor, VS Code, Codex, Gemini CLI,
Claude Desktop, or any other MCP host:

- **search and triage findings**, e.g. *"open criticals with a public exploit on prod"*
- read finding detail (evidence, steps, mitigation, CVE/CWE) and **update state or
  severity**
- explore **assets** (exposure, sensitivity, risk) and **engagements**
- create assets, findings and engagements, and comment on them

Sign-in is a **browser approval, like `strobes login`**. You don't paste API keys, and one
login covers this server, [strobes-agents-mcp](https://github.com/strobes-co/strobes-agents-mcp)
and the Strobes CLI.

---

## Quick start

**Claude Code (plugin):**
```
/plugin marketplace add strobes-co/strobes-mcp
/plugin install strobes-mcp@strobes
/strobes-mcp:login
```
The plugin brings the server, a skill, and slash commands
(`/strobes-mcp:login`, `:triage`, `:posture`).

**Any MCP client, one command** (needs [uv](https://docs.astral.sh/uv/)):
```bash
uvx --from git+https://github.com/strobes-co/strobes-mcp strobes-mcp setup
```
`setup` signs you in, then adds the server to every client it finds: Claude Code, Claude
Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI. You can also name the clients:
`… setup claude-code cursor`.

**Or add it by hand.** You don't need any env vars, because the server reads the shared
login:
```bash
claude mcp add strobes -- uvx --from git+https://github.com/strobes-co/strobes-mcp strobes-mcp
```
Then ask your agent to *"sign in to Strobes"*.

`strobes-mcp install <client> [--dry-run]` writes a single client's config:
`claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf`, `codex`, `gemini`, or `json`
for anything else.

---

## Authentication

There are three ways to authenticate. Pick whichever fits your setup.

1. **Browser sign-in (recommended).** Use `strobes-mcp login [--url https://acme.strobes.co]`,
   or the `strobes_login` tool from inside your agent. This is the same device flow as
   the Strobes CLI: you confirm a code, pick the organization (and optionally a default
   workspace), and click **Authorize**. Strobes then issues *your* API key, so the agent
   acts with exactly your permissions.
2. **Shared with the Strobes CLI.** If you've already run `strobes login`, there's
   nothing to do. Both tools use the same profile store:
   - macOS `~/Library/Application Support/strobes-ai/config.json`
   - Linux `~/.config/strobes-ai/config.json`
   - Windows `%APPDATA%\strobes-ai\config.json`

   The file is written with `0600` permissions. `STROBES_AI_HOME` overrides the location.
3. **Environment variables**, for CI and containers. If `STROBES_API_KEY` is set, the
   environment is used *instead of* the stored login, never mixed with it field by field,
   so a key can't end up sent to another org's server. Set the URL, key and organization
   together. A profile you pick explicitly (`--profile`, `strobes_use_profile`, or a
   just-finished sign-in) always uses the stored login.

| Variable | Meaning |
|---|---|
| `STROBES_URL` (or `STROBES_HOST`) | Tenant URL, e.g. `https://acme.strobes.co` |
| `STROBES_API_KEY` (or `STROBES_API_TOKEN`) | A MasterKey from *Settings → API access* |
| `STROBES_ORGANIZATION_ID` | Organization UUID |
| `STROBES_PROFILE` | Which stored profile to use (multi-org) |
| `STROBES_WORKSPACE_ID` | Default workspace for tools that take `workspace_id` |
| `STROBES_VERIFY_TLS=false` | Self-signed / dev servers |
| `STROBES_BASE_URL` + `STROBES_TENANT_HOST` | Dial one URL but send another `Host` (local dev) |

**Multiple organizations:** sign in to each one with `login --profile eu --url …`. Then
switch with `strobes-mcp use eu` (this also changes the CLI's default), or use the
`strobes_use_profile` tool for a single session. To pin one client to a profile, use
`install … --profile eu`.

Other commands: `strobes-mcp status` checks who you are and tests the connection,
`profiles` lists your profiles, and `logout` signs you out.

---

---

## Tools

| Group | Tools |
|---|---|
| Session | `strobes_whoami`, `strobes_login`, `strobes_login_status`, `strobes_use_profile`, `strobes_logout`, `strobes_reference` |
| Findings | `list_findings`, `get_finding`, `create_finding`, `update_findings`, `add_finding_comment`, `list_comments` |
| Assets | `list_assets`, `get_asset`, `create_asset` |
| Engagements | `list_engagements`, `create_engagement`, `add_engagement_comment` |

Prompts: `triage_findings(scope)` and `asset_risk_summary(asset)`.

How the tools are designed:

- **Names, not codes.** Tools take and return names (`severity=["critical"]`,
  `state="accepted_risk"`) instead of numeric codes. Typed filters (`open_only`,
  `severity`, `state`, `type`) cover the common cases.
- **Search.** `search_query` is DjangoQL, e.g. `cvss >= 7 and exploit_available = "true"`,
  `title ~ "sql"`, `asset.id = 12` ([reference](skills/strobes/references/query-language.md);
  every example there is checked against the API).
- **Safe bulk updates.** `update_findings` checks what the query matches before changing
  anything. It refuses empty or >200 matches unless you allow it, and it reports which
  changes actually applied. Strobes applies bulk updates in the background, or routes them
  to an approver when your org requires approval for state changes.
- **Annotations.** Every tool declares MCP annotations, so hosts can auto-approve reads
  and confirm `update_findings` / creates.
- **Compact output.** Output is compact JSON, and long finding text is truncated.

---

## Remote / shared deployment (streamable HTTP)

```bash
strobes-mcp serve --http --host 0.0.0.0 --port 8765 \
  --require-header-auth --allowed-host mcp.internal.example
```
Each client sends its own credentials:
```json
{
  "mcpServers": {
    "strobes": {
      "type": "http",
      "url": "https://mcp.internal.example/mcp",
      "headers": {
        "Authorization": "Bearer <Strobes MasterKey>",
        "X-Strobes-Url": "https://acme.strobes.co",
        "X-Strobes-Organization-Id": "<org uuid>"
      }
    }
  }
}
```

What remote mode guarantees:

- **Header credentials only.** With `--require-header-auth`, the server never falls back
  to a login stored on the host.
- **No host-affecting tools.** Sign-in, sign-out, profile switching and `upload_file(local_path=…)`
  are refused to HTTP clients. `strobes_whoami` never lists the host's profiles.
- **Allowed URLs only.** `X-Strobes-Url` must be `https` and match
  `STROBES_MCP_ALLOWED_URLS` (default `*.strobes.co`; comma-separated globs), so callers
  can't point the server at internal addresses.
- **Host-header checks.** `--allowed-host` turns on Host-header (DNS-rebinding) checks for
  your public name. Without it, a non-localhost bind turns them off so requests through a
  load balancer aren't rejected.

For a single-tenant deployment, leave out `--require-header-auth` and `X-Strobes-Url`, and
set `STROBES_URL` / `STROBES_ORGANIZATION_ID` on the server. Clients then only send their
key. A container image is in [`Dockerfile`](Dockerfile).

---

## Development

```bash
uv sync
uv run pytest                 # unit tests (mocked HTTP, in-memory MCP session)
uv run strobes-mcp serve      # stdio; try it with `npx @modelcontextprotocol/inspector`
```

<!-- mcp-name: io.github.strobes-co/strobes-mcp -->
