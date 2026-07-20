# Compute Engine Audit Skill

## Objective
Audit Compute Engine VM instances for public exposure, default service
account overprivilege, and hardened-VM configuration gaps.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Instance Inventory
```shell
gcloud compute instances list \
  --project={project} \
  --format="json(name,zone,networkInterfaces,serviceAccounts,\
shieldedInstanceConfig,metadata)"
```

### Step 2: Public IP Exposure
Flag instances where `networkInterfaces[].accessConfigs[].natIP` is set
(an external IP is assigned).

### Step 3: Default Service Account With Broad Scopes
Flag instances where `serviceAccounts[].email` ends in
`-compute@developer.gserviceaccount.com` (the default Compute Engine SA)
AND `serviceAccounts[].scopes` includes
`https://www.googleapis.com/auth/cloud-platform` (full project access).
This is one of the most common real-world GCP misconfigurations.

### Step 4: OS Login and Serial Port
Check instance and project metadata for:
- `enable-oslogin` not `TRUE` → OS Login disabled, centralized SSH key
  management and 2FA are bypassed.
- `serial-port-enable` set to `TRUE` → serial console access enabled.

### Step 5: Shielded VM Configuration
Flag instances where `shieldedInstanceConfig.enableSecureBoot`,
`enableVtpm`, or `enableIntegrityMonitoring` is `false`.

## Severity Guidelines
- CRITICAL: Public IP + default service account with `cloud-platform` scope
  (internet-reachable instance with near-project-owner API access)
- HIGH: Default service account with `cloud-platform` scope (no public IP)
- MEDIUM: Public IP present without the above, OS Login disabled
- LOW: Serial port access enabled, Shielded VM features disabled

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "compute",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
