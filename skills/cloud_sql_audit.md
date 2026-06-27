# Cloud SQL Exposure Audit Skill

## Objective
Audit Cloud SQL instances for public network exposure, backup posture,
and authorized network configuration.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Instance Inventory
```shell
gcloud sql instances list \
  --project={project} \
  --format="json(name,settings.ipConfiguration,settings.backupConfiguration,\
databaseVersion,settings.availabilityType)"
```

### Step 2: Public IP and Authorized Network Check
Flag instances where:
- `settings.ipConfiguration.ipv4Enabled` is true AND
- `settings.ipConfiguration.authorizedNetworks` contains `0.0.0.0/0`,
  OR no SSL/TLS enforcement is configured

### Step 3: Backup Configuration
Flag instances where `settings.backupConfiguration.enabled` is false, or
`settings.backupConfiguration.transactionLogRetentionDays` is below 7.

### Step 4: Private Services Access Check
For instances with public IP enabled, check whether a corresponding
Private Services Access connection exists for the same VPC, which would
allow migrating to private-only connectivity.

### Step 5: Cross-Domain Correlation
If a public-IP-enabled instance is also referenced in a GKE workload
identity binding (from the GKE audit), add cross_domain_tags:
["cloud-sql-instance:{instance_name}"]
This is the most common chain pattern: GKE workload + exposed Cloud SQL.

## Severity Guidelines
- CRITICAL: Public IP enabled with 0.0.0.0/0 in authorized networks
- HIGH: Public IP enabled without SSL enforcement
- MEDIUM: Backup retention below 7-day baseline
- INFO: Instance with no query activity in 14+ days (cost optimisation
  candidate, not a security finding)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "cloud_sql",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
