# BigQuery Audit Skill

## Objective
Audit BigQuery dataset access control for public exposure and missing
customer-managed encryption.

## Tools Available
- shell: Execute `bq` CLI commands (bundled with the Google Cloud SDK)

## Execution Steps

### Step 1: Dataset Inventory
```shell
bq ls --format=prettyjson --max_results=1000 {project}:
```

### Step 2: Dataset Access Control
```shell
bq show --format=prettyjson {project}:{dataset}
```
Inspect the `access` list. Flag any entry where `specialGroup` is
`allAuthenticatedUsers`, or where `iamMember`/`userByEmail` is
`allUsers`/`allAuthenticatedUsers`.

### Step 3: Encryption
Flag datasets where `defaultEncryptionConfiguration.kmsKeyName` is absent
if the dataset's labels indicate sensitive data (e.g.
`data-classification: pii`).

## Severity Guidelines
- CRITICAL: Dataset readable/writable by `allUsers`/`allAuthenticatedUsers`
- HIGH: Dataset labelled PII without a customer-managed encryption key
- MEDIUM: Dataset has no labels documenting owner/classification
- INFO: Dataset with no tables (housekeeping candidate)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "bigquery",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
