# Org Policy & Logging Audit Skill

## Objective
Audit which organization policy guardrails are enforced at the project
level, and whether audit logs are durably exported.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Org Policy Constraint Coverage
```shell
gcloud resource-manager org-policies list --project={project} --format=json
```
Check whether each of these commonly-recommended constraints is present
and enforced:
- `constraints/iam.disableServiceAccountKeyCreation`
- `constraints/compute.requireOsLogin`
- `constraints/compute.vmExternalIpAccess` (should be a deny/allowlist,
  not unrestricted)
- `constraints/storage.uniformBucketLevelAccess`
- `constraints/sql.restrictPublicIp`

Flag each constraint that is absent from the list (not set at this level;
it may still be inherited from a folder/org — note this in the finding).

### Step 2: Log Sink Coverage
```shell
gcloud logging sinks list --project={project} --format="json(name,destination,filter)"
```
Flag if there are zero sinks — audit logs are only retained for the
default Cloud Logging retention window with no durable export.

### Step 3: Default Sink Status
```shell
gcloud logging settings describe --project={project} --format=json
```
Flag if `disableDefaultSink` is `true` and Step 2 found no other sinks —
audit logs may not be retained at all.

## Severity Guidelines
- HIGH: Default log sink disabled with no replacement sink configured
- MEDIUM: A recommended org policy constraint (Step 1) is not enforced at
  the project level; no log sinks configured at all
- INFO: Constraint is unset at project level but likely inherited from a
  parent folder/org (informational — recommend verifying inheritance)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "org_policy",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
