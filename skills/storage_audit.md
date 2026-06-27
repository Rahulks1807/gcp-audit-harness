# Cloud Storage Posture Audit Skill

## Objective
Audit Cloud Storage bucket-level access controls, legacy ACL usage, and
public exposure across specified projects.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Bucket Inventory
```shell
gcloud storage buckets list \
  --project={project} \
  --format="json(name,iamConfiguration.uniformBucketLevelAccess,\
iamConfiguration.publicAccessPrevention,labels)"
```

### Step 2: IAM Policy and Legacy ACL Check
For each bucket:
```shell
gcloud storage buckets get-iam-policy gs://{bucket_name} --format=json
```
Flag bindings granting `allUsers` or `allAuthenticatedUsers` any role.
Cross-reference with `iamConfiguration.uniformBucketLevelAccess.enabled` —
if false, the bucket may also carry legacy ACLs outside the IAM policy
view; flag these for manual ACL inspection.

### Step 3: Public Access Prevention
Flag buckets where `iamConfiguration.publicAccessPrevention` is not
`enforced`, particularly for buckets with labels indicating sensitive
data (e.g. a `data-classification: pii` label).

### Step 4: Stale Service Account Access
Cross-reference bucket IAM bindings against the IAM domain's service
account key age findings. If a service account with a stale key (90+ days)
holds `roles/storage.objectAdmin` or `objectCreator` on a bucket, add
cross_domain_tags: ["service-account:{sa_email}", "bucket:{bucket_name}"]

## Severity Guidelines
- CRITICAL: allUsers or allAuthenticatedUsers granted on a bucket holding
  PII-labelled data
- HIGH: allUsers/allAuthenticatedUsers granted on any bucket without a
  data classification label (unclear sensitivity, assume sensitive)
- MEDIUM: Uniform bucket-level access disabled (legacy ACLs possible)
- INFO: Bucket has no labels at all (governance gap, not a security risk
  on its own)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "storage",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
