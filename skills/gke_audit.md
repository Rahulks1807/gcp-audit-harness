# GKE Workload Security Audit Skill

## Objective
Audit GKE cluster and workload security configuration, with focus on
workload identity scope, binary authorization, and node security posture.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Cluster Inventory and Security Settings
```shell
gcloud container clusters list \
  --project={project} \
  --format="json(name,location,binaryAuthorization,workloadIdentityConfig,\
nodePools[].management.autoUpgrade,releaseChannel)"
```

### Step 2: Workload Identity Binding Scope
For each cluster with workload identity enabled, list the IAM bindings
held by Kubernetes service accounts (KSAs) mapped to Google service accounts:
```shell
gcloud iam service-accounts get-iam-policy {gsa_email} --format=json
```
Flag any binding where a KSA has `roles/iam.workloadIdentityUser` AND the
underlying GSA holds a role granting access to another service (e.g.
Cloud SQL Client, Storage Admin) at project level rather than scoped to a
specific resource and namespace. This is the most common path to a
cross-domain finding, since it often connects directly to a Cloud SQL or
Storage finding.

### Step 3: Binary Authorization Check
Flag clusters where `binaryAuthorization.evaluationMode` is not
`PROJECT_SINGLETON_POLICY_ENFORCE`.

### Step 4: Node Security
Flag node pools where `management.autoUpgrade` is false, and clusters not
enrolled in a release channel (`releaseChannel.channel` is `UNSPECIFIED`).

### Step 5: Cross-Domain Correlation
For any workload identity binding found in Step 2 that grants access to a
Cloud SQL instance or Storage bucket, add cross_domain_tags:
["service-account:{gsa_email}", "gke-workload-identity:{cluster_name}"]

## Severity Guidelines
- CRITICAL: Workload identity binding grants cluster-wide (not namespace-
  scoped) access to a service holding sensitive data (Cloud SQL, Storage
  with PII)
- HIGH: Binary Authorization disabled on a production cluster
- MEDIUM: Node auto-upgrade disabled, no release channel enrollment
- INFO: Non-production cluster missing recommended settings

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "gke",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
