# KMS & Secret Manager Audit Skill

## Objective
Audit Cloud KMS key hygiene and Secret Manager access scope for
overly-broad IAM bindings and missing rotation.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: KMS Keyring and Key Inventory
```shell
gcloud kms keyrings list --project={project} --location={region} --format="json(name)"

gcloud kms keys list \
  --keyring={keyring} --location={region} --project={project} \
  --format="json(name,rotationPeriod,primary.state)"
```

### Step 2: Key Rotation
Flag keys where `rotationPeriod` is unset — rotation is disabled and key
material may be used indefinitely.

### Step 3: Key IAM Policy
```shell
gcloud kms keys get-iam-policy {key} \
  --keyring={keyring} --location={region} --project={project} --format=json
```
Flag any binding granting `roles/cloudkms.cryptoKeyEncrypterDecrypter` or
`roles/cloudkms.admin` to `allUsers`/`allAuthenticatedUsers`.

### Step 4: Secret Manager Inventory
```shell
gcloud secrets list --project={project} --format="json(name,createTime,replication)"
```

### Step 5: Secret IAM Policy
```shell
gcloud secrets get-iam-policy {secret} --project={project} --format=json
```
Flag any binding granting `allUsers`/`allAuthenticatedUsers` access to a
secret's value.

## Severity Guidelines
- CRITICAL: `allUsers`/`allAuthenticatedUsers` can decrypt with a KMS key or
  access a secret's payload
- HIGH: KMS key has no rotation period configured
- MEDIUM: Secret has no labels/rotation policy documenting its owner
- INFO: Keyring/secret with no IAM bindings beyond the project owner

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "kms_secrets",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
