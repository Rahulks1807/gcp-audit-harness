# Pub/Sub Audit Skill

## Objective
Audit Pub/Sub topic and subscription IAM policies for overly-broad public
access.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Topic and Subscription Inventory
```shell
gcloud pubsub topics list --project={project} --format="json(name)"
gcloud pubsub subscriptions list --project={project} --format="json(name,topic,ackDeadlineSeconds,expirationPolicy)"
```

### Step 2: Topic IAM Policy
```shell
gcloud pubsub topics get-iam-policy {topic} --project={project} --format=json
```
Flag any binding granting `roles/pubsub.publisher` or
`roles/pubsub.editor` to `allUsers`/`allAuthenticatedUsers`.

### Step 3: Subscription IAM Policy
```shell
gcloud pubsub subscriptions get-iam-policy {subscription} --project={project} --format=json
```
Flag any binding granting `roles/pubsub.subscriber` to
`allUsers`/`allAuthenticatedUsers`.

### Step 4: Subscription Expiration
Flag subscriptions with `expirationPolicy.ttl` unset (never expires) and
no recent activity — indicates an orphaned subscription accumulating cost
and potential access surface.

## Severity Guidelines
- CRITICAL: `allUsers`/`allAuthenticatedUsers` can publish/subscribe on a
  topic whose name suggests production data
- HIGH: `allUsers`/`allAuthenticatedUsers` granted any Pub/Sub role
- INFO: Subscription with no expiration policy and no recent traffic

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "pubsub",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
