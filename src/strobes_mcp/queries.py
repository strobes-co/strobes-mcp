"""GraphQL documents for the Strobes public endpoint (/api/public/graphql/).

Mutation documents must contain the mutation field name verbatim — the backend's
MasterKey allowlist (strobes/connectors/permissions.py) matches on it.
"""

ASSET_LIST = """
  id name target type sensitivity exposed riskScore hostname ipaddress
  created updated tags { name }
"""
ASSET_DETAIL = ASSET_LIST + """
  os cpe macAddress region accountId resourceId cloudType defaultBranch
  latestReleaseTag lastCommittedOn webserver technologyUsed waf cdn asn
  packageCount isActive fields sensitivityReasoning exposureReasoning
"""
BUG_LIST = """
  id title severity state bugLevel cvss epssScore dueDate slaViolated
  exploitAvailable patchAvailable prioritizationScore created updated
  asset { id name }
"""
BUG_DETAIL = BUG_LIST + """
  description mitigation stepsToReproduce evidence cvssV3 cvssV3AttackVector
  cvssV4 cvssV4AttackVector attackVector zeroDayAvailable isWormable cisaDueDate
  exploitInfo patchInfo hostname ipaddress port links fields
  cve { cveId title cvss } cwe { cweId type } bugTags { name }
  engagements { id name }
"""
ENGAGEMENT = """
  id engagementCustomId name state scheduledDate deliveryDate subscribedServices
  isSelfManagedEngagement isAgenticAssessment engagementCompletion assessmentsCount
  created updated
"""
COMMENT = "id comment internal created bugId engagementId commentedBy { email firstName lastName }"

ASSETS = f"""
query AllAssets($org: UUID, $q: String, $page: Int, $size: Int, $order: [String]) {{
  allAssets(organizationId: $org, searchQuery: $q, page: $page, pageSize: $size,
            orderBy: $order) {{
    hasNext objects {{ {ASSET_LIST} }}
  }}
}}"""

ASSET_GET = f"""
query GetAsset($org: UUID, $q: String) {{
  allAssets(organizationId: $org, searchQuery: $q, page: 1, pageSize: 1) {{
    objects {{ {ASSET_DETAIL} }}
  }}
}}"""

BUGS = f"""
query AllBugs($org: UUID, $q: String, $page: Int, $size: Int, $order: [String]) {{
  allBugs(organizationId: $org, searchQuery: $q, page: $page, pageSize: $size,
          orderBy: $order) {{
    hasNext objects {{ {BUG_LIST} }}
  }}
}}"""

BUG_IDS = """
query BugIds($org: UUID, $q: String, $size: Int) {
  allBugs(organizationId: $org, searchQuery: $q, page: 1, pageSize: $size) {
    hasNext objects { id }
  }
}"""

BUG_GET = f"""
query GetBug($org: UUID, $q: String) {{
  allBugs(organizationId: $org, searchQuery: $q, page: 1, pageSize: 1) {{
    objects {{ {BUG_DETAIL} }}
  }}
}}"""

ENGAGEMENTS = f"""
query AllEngagements($org: UUID, $q: String, $page: Int, $size: Int, $order: [String]) {{
  allEngagements(organizationId: $org, searchQuery: $q, page: $page, pageSize: $size,
                 orderBy: $order) {{
    totalCount hasNext objects {{ {ENGAGEMENT} }}
  }}
}}"""

COMMENTS = f"""
query AllComments($org: UUID!, $bug: Int, $eng: UUID, $page: Int, $size: Int) {{
  allComments(organizationId: $org, bugId: $bug, engagementId: $eng, page: $page,
              pageSize: $size) {{
    totalCount hasNext objects {{ {COMMENT} }}
  }}
}}"""

# ------------------------------------------------------------------ mutations
CREATE_ASSET = f"""
mutation CreateAsset($org: UUID, $name: String, $type: Int, $url: String,
    $hostname: String, $ip: String, $sensitivity: Int, $exposed: Int, $tags: [String],
    $cloudType: Int, $customFields: GenericScalar) {{
  createAsset(organizationId: $org, name: $name, type: $type, url: $url,
      hostname: $hostname, ipaddress: $ip, sensitivity: $sensitivity, exposed: $exposed,
      tags: $tags, cloudType: $cloudType, customFields: $customFields) {{
    asset {{ {ASSET_LIST} }}
  }}
}}"""

BUG_CREATE = f"""
mutation BugCreate($org: UUID!, $title: String!, $description: String!, $level: Int!,
    $severity: Int, $assets: [Int], $mitigation: String, $steps: String,
    $evidence: String, $cves: [String], $cwes: [Int], $tags: [String],
    $engagement: String, $web: JSONString, $code: JSONString, $mobile: JSONString,
    $network: JSONString, $cloud: JSONString, $package: JSONString, $cvssV3: Float) {{
  bugCreate(organizationId: $org, title: $title, description: $description,
      bugLevel: $level, severity: $severity, selectedAssets: $assets,
      mitigation: $mitigation, stepsToReproduce: $steps, evidence: $evidence,
      cveList: $cves, cweList: $cwes, tags: $tags, engagementId: $engagement,
      web: $web, code: $code, mobile: $mobile, network: $network, cloud: $cloud,
      package: $package, cvssV3: $cvssV3) {{
    bug {{ {BUG_LIST} }}
  }}
}}"""

BUG_BULK_UPDATE = """
mutation BugBulkUpdate($org: UUID!, $q: String, $state: Int, $severity: Int) {
  bugBulkUpdate(organizationId: $org, searchQuery: $q, state: $state, severity: $severity) {
    bugs { id title state severity }
  }
}"""

ADD_BUG_COMMENT = f"""
mutation AddBugComment($org: UUID!, $bug: Int!, $comment: String!, $internal: Boolean) {{
  addBugComment(organizationId: $org, bugId: $bug, comment: $comment, internal: $internal) {{
    comment {{ {COMMENT} }}
  }}
}}"""

CREATE_ENGAGEMENT = f"""
mutation CreateEngagement($org: UUID, $name: String, $scheduled: Date, $delivery: Date,
    $services: [String], $plans: Int, $selfManaged: Boolean, $assessment: JSONString,
    $summary: String, $fields: JSONString, $documents: [Int]) {{
  createEngagement(organizationId: $org, name: $name, scheduledDate: $scheduled,
      deliveryDate: $delivery, subscribedServices: $services, plans: $plans,
      isSelfManaged: $selfManaged, assessmentData: $assessment,
      executiveSummary: $summary, fields: $fields, documentIds: $documents) {{
    engagement {{ {ENGAGEMENT} }}
  }}
}}"""

ADD_ENGAGEMENT_COMMENT = f"""
mutation AddEngagementComment($org: UUID!, $eng: UUID!, $comment: String!) {{
  addEngagementComment(organizationId: $org, engagementId: $eng, comment: $comment) {{
    comment {{ {COMMENT} }}
  }}
}}"""
