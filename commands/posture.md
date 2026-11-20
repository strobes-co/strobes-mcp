---
description: Quick security posture snapshot from Strobes
---
Give me a security posture snapshot from Strobes: counts of open findings by severity
(`list_findings(open_only=true, severity=[x], page_size=100)` per severity, noting when there
are more pages), the 10 riskiest open findings, the highest-risk internet-exposed assets
(`list_assets(order_by=['-risk_score'])`), and engagements in progress
(`list_engagements`). Keep it to one compact report with suggested next steps.
