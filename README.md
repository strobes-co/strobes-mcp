# strobes-mcp

Model Context Protocol (MCP) server for the **Strobes** platform. It lets Claude
Code (or any MCP host) manage **assets**, **findings/vulnerabilities** and
**engagements** through the Strobes public GraphQL API.

It wraps the official [`strobes-gql-client`](https://github.com/strobes-co/strobes-gql-client),
so all per-operation field selection and error handling come from the client.

> For AI-workspace and agent control (spin up / stop agent tasks, chat with
> Strobes AI agents) use the companion **[strobes-agents-mcp](../strobes-agents-mcp)**.

## Tools
| Tool | Purpose |
|------|---------|
| `strobes_whoami` | Connectivity check + enum reference |
| `list_assets` / `get_asset` / `create_asset` | Asset management |
| `list_findings` / `create_finding` / `update_findings` | Finding management |
| `add_finding_comment` | Comment on a finding |
| `list_engagements` / `create_engagement` | Engagement management |
| `add_engagement_comment` | Comment on an engagement |
| `list_comments` | Read comments on a finding/engagement |

## Configuration (environment variables)
| Variable | Required | Meaning |
|----------|----------|---------|
| `STROBES_HOST` | yes | Tenant host, e.g. `acme.strobes.co` |
| `STROBES_API_TOKEN` | yes | Strobes **MasterKey** (Settings → API Access) |
| `STROBES_ORGANIZATION_ID` | yes | Organization UUID |
| `STROBES_BASE_URL` | no | Override scheme+host (self-hosted/on-prem/local, e.g. `http://localhost`) |
| `STROBES_TENANT_HOST` | no | Override the `Host` header (local/dev tenant routing) |
| `STROBES_VERIFY_TLS` | no | `false` to disable TLS verification (default `true`) |

## Install as a Claude Code plugin (marketplace)
```
/plugin marketplace add strobes-co/strobes-mcp      # or a local path to this repo
/plugin install strobes-mcp@strobes
```
Then set `STROBES_HOST`, `STROBES_API_TOKEN` and `STROBES_ORGANIZATION_ID` in
your environment. The bundled `strobes` MCP server launches via `uv`.

## Install as a plain MCP server
Requires [`uv`](https://docs.astral.sh/uv/). Add to your MCP host config:
```json
{
  "mcpServers": {
    "strobes": {
      "command": "uv",
      "args": ["run", "--directory", "/abs/path/to/strobes-mcp", "strobes-mcp"],
      "env": {
        "STROBES_HOST": "acme.strobes.co",
        "STROBES_API_TOKEN": "...",
        "STROBES_ORGANIZATION_ID": "..."
      }
    }
  }
}
```

## Development / testing
```
STROBES_HOST=... STROBES_API_TOKEN=... STROBES_ORGANIZATION_ID=... \
  uv run --with 'mcp<2' --with requests --with sgqlc python tests/test_e2e.py
```

## Dependency note
`pyproject.toml` pins `strobes-graphql-client` to the git branch
`feat/agent-workspace-mcp-ops` (which carries the agent/workspace client
support). Once that branch is merged, repoint `[tool.uv.sources]` to the default
branch:
```toml
[tool.uv.sources]
strobes-graphql-client = { git = "https://github.com/strobes-co/strobes-gql-client.git" }
```
