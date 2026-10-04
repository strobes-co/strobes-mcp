# Strobes search query language

Used by `search_query` on `list_assets`, `list_findings`, `list_engagements`.

## Shape
`<field> <operator> <value> [and|or <field> <operator> <value> ...]`

## Operators
- `=`, `!=`, `>`, `<`, `>=`, `<=`
- `in (v1,v2,...)` / `not in (...)`
- `like` (substring, use with strings)
- boolean values: `true` / `false`

## Common finding (bug) fields
- `id` — numeric id (e.g. `id = 42`, `id in (1,2,3)`)
- `severity` — 1..5 (5=Critical)
- `state` — 1=Open,2=Closed,3=False Positive,4=Accepted Risk,5=Duplicate,6=Out of Scope
- `bug_level` — 1=Code,2=Web,3=Mobile,4=Network,5=Cloud,6=Package
- `cvss` — float, e.g. `cvss >= 7`
- `exploit_available` — boolean
- `patch_available` — boolean
- `sla_violated` — boolean
- `title` — `title like 'sql injection'`
- `tags` — `tags in (production)`

## Common asset fields
- `id`, `name`, `target`
- `type` — 1=Web,2=Mobile,3=Network,4=Cloud,7=Code
- `risk_score` — numeric, e.g. `risk_score >= 70`
- `sensitivity` — 1..4
- `exposed` — 1=Public,2=Internal
- `tags` — `tags in (external,production)`

## Examples
- `severity = 5 and state = 1` — critical, still open
- `cvss >= 9 and exploit_available = true` — weaponised criticals
- `type = 1 and risk_score >= 50` — risky web assets
- `tags in (pci) and state != 2` — unresolved on PCI-tagged items
