# Artifact Registry Audit Skill

## Objective
Audit Artifact Registry repositories for public read/write access.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Repository Inventory
```shell
gcloud artifacts repositories list --project={project} \
  --format="json(name,format,mode,createTime)"
```

### Step 2: Repository IAM Policy
```shell
gcloud artifacts repositories get-iam-policy {repository} \
  --location={location} --project={project} --format=json
```
Flag any binding granting `roles/artifactregistry.reader` or
`roles/artifactregistry.writer` to `allUsers`/`allAuthenticatedUsers`.

### Step 3: Repository Mode
Flag repositories in `REMOTE_REPOSITORY` mode that proxy an upstream
registry without an allowlist — a supply-chain risk if the upstream is
compromised.

## Severity Guidelines
- CRITICAL: `allUsers` granted write access (anyone can push images/packages)
- HIGH: `allUsers`/`allAuthenticatedUsers` granted read access (private
  images/packages exposed publicly)
- MEDIUM: Remote repository proxying an upstream with no allowlist
- INFO: Repository with no cleanup policy configured

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "artifact_registry",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
