# Networking Audit Skill

## Objective
Audit Network Connectivity Center topology, VPC configurations, and hybrid
connectivity health across specified GCP projects.

## Tools Available
- shell: Execute gcloud CLI commands
- python: Run Python scripts for complex analysis

## Execution Steps

### Step 1: NCC Hub and Spoke Inventory
```shell
gcloud network-connectivity hubs list \
  --format="json(name,state,description)" \
  --project={project}

gcloud network-connectivity spokes list \
  --format="json(name,state,hub,linkedVpnTunnels,linkedInterconnectAttachments,linkedRouterApplianceInstances)" \
  --project={project}
```

### Step 2: BGP Session Health
```shell
gcloud compute routers get-status {router_name} \
  --region={region} \
  --project={project} \
  --format="json(result.bgpPeerStatus)"
```

### Step 3: CIDR Overlap Detection
For each VPC spoke, collect all subnet CIDR ranges and check for overlaps
using Python's ipaddress module. Flag any overlapping ranges as HIGH severity.

### Step 4: Stale Spoke Detection
Identify spokes with state != ACTIVE or spokes where linkedVpnTunnels
tunnels have status != ESTABLISHED.

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "networking",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}

## Severity Guidelines
- CRITICAL: BGP session down on active production spoke
- HIGH: CIDR overlap between spokes, stale spoke with no traffic >7 days
- MEDIUM: NCC hub missing description/labels, spoke in CREATING state >1hr
- INFO: Unused spoke (no traffic >30 days but state is ACTIVE)
