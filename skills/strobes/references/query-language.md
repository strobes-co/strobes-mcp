# Strobes search query language

`search_query` on `list_assets`, `list_findings`, `list_engagements` and
`update_findings` is **DjangoQL**. Every example below was checked against the API.

## Syntax
- Compare: `=`, `!=`, `>`, `>=`, `<`, `<=`
- Contains / doesn't contain (case-insensitive): `~`, `!~` — `title ~ "sql injection"`
- Lists: `in (...)`, `not in (...)` — `state in (0, 1)`, `id in (101, 102)`
- Combine with `and` / `or`, group with `( )`
- Strings and dates in quotes: `"prod"`, `"2027-01-01"`
- Relations use dots: `asset.id = 12`, `asset.name ~ "payments"`
- Yes/no flags are **strings**: `exploit_available = "true"` (not `= true`)
- There is no `like` operator — use `~`

## Codes
| field | values |
|---|---|
| finding `severity` | 1 info, 2 low, 3 medium, 4 high, 5 critical |
| finding `state` | 0 new, 1 active, 2 resolved, 3 duplicate, 4 not applicable, 5 committed, 6 accepted risk, 7 won't fix |
| finding `bug_level` | 1 code, 2 web, 3 mobile, 4 network, 5 cloud, 6 package |
| asset `type` | 1 web, 2 mobile, 3 network, 4 cloud, 5 website, 6 API service, 7 code repo … (`strobes_reference` has more) |
| asset `sensitivity` | 0 none, 1 low, 2 medium, 3 high, 4 critical |
| asset `exposed` | 1 high (internet-facing), 2 medium, 3 low |
| engagement `state` | 1 new, 2 in progress, 4 completed, 5 retest requested, 6 finished, 7 on hold |

"Open" findings are `state in (0, 1)`.

## Findings
- `severity = 5 and state in (0, 1)` — open criticals
- `cvss >= 7 and exploit_available = "true"` — exploitable, high CVSS
- `title ~ "sql"` — title contains "sql"
- `asset.id = 12` / `asset.name ~ "payments"` — on an asset
- `finding_tags = "pci"` — tagged findings; `asset_tags = "prod"` — on tagged assets
- `due_date < "2027-01-01"` — due before a date
- `id in (101, 102, 103)` — exact set (use this for `update_findings`)

## Assets
- `type = 1` — web apps; `exposed = 1` — internet-facing
- `sensitivity >= 3` — high/critical business sensitivity
- `risk_score >= 70`
- `target ~ "example.com"`, `name ~ "payments"`
- `asset_tags = "prod"`

## Engagements
- `state = 2` — in progress; `name ~ "web"`
