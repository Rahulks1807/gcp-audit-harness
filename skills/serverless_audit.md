# Cloud Run & Cloud Functions Audit Skill

## Objective
Audit serverless compute (Cloud Run services and Cloud Functions) for
unauthenticated public invocation and overly broad ingress settings.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Cloud Run Inventory
```shell
gcloud run services list --project={project} --platform=managed \
  --format="json(metadata.name,status.url,spec.template.spec.containers,\
metadata.annotations)"
```

### Step 2: Cloud Run IAM Policy
```shell
gcloud run services get-iam-policy {service} --region={region} \
  --project={project} --format=json
```
Flag any binding granting `roles/run.invoker` to `allUsers` — the service
is publicly invokable without authentication.

### Step 3: Cloud Functions Inventory
```shell
gcloud functions list --project={project} --v2 \
  --format="json(name,httpsTrigger,ingressSettings,serviceConfig)"
```

### Step 4: Cloud Functions IAM Policy
```shell
gcloud functions get-iam-policy {function} --region={region} \
  --project={project} --format=json
```
Flag any binding granting `roles/cloudfunctions.invoker` to `allUsers`.

### Step 5: Ingress Settings
Flag Cloud Run services/Cloud Functions where ingress allows traffic from
`all` rather than `internal-only` or `internal-and-cloud-load-balancing`,
combined with public invoker access from Steps 2/4.

## Severity Guidelines
- CRITICAL: Public invoker (`allUsers`) + ingress from `all` + service
  name/env vars suggest access to sensitive backends (e.g. references a
  Cloud SQL or Storage resource also flagged elsewhere)
- HIGH: Public invoker (`allUsers`) granted with no additional context
- MEDIUM: Ingress allows `all` traffic even though invoker is restricted
- INFO: Service with no traffic in the last 14 days (cost-optimisation
  candidate)

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "serverless",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
