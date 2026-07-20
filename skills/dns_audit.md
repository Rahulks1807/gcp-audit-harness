# Cloud DNS Audit Skill

## Objective
Audit Cloud DNS managed zones for missing DNSSEC and unintended public
visibility.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Managed Zone Inventory
```shell
gcloud dns managed-zones list --project={project} \
  --format="json(name,dnsName,visibility,dnssecConfig)"
```

### Step 2: DNSSEC Coverage
For each zone with `visibility` = `public`, flag it if
`dnssecConfig.state` is not `on` — the zone is vulnerable to cache
poisoning/spoofing attacks.

### Step 3: Unexpected Public Zones
Flag any zone with `visibility` = `public` whose name/dnsName suggests an
internal-only purpose (e.g. contains `internal`, `corp`, `staging`) as a
possible unintended public exposure — recommend manual review.

## Severity Guidelines
- HIGH: Public zone with DNSSEC disabled
- MEDIUM: Public zone whose naming suggests it should be private
- INFO: Private zone (no external exposure risk, informational only)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "dns",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
