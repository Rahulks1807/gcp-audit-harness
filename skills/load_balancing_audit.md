# Load Balancing & Cloud Armor Audit Skill

## Objective
Audit external load balancer backends for missing Cloud Armor (WAF)
coverage.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Backend Service Inventory
```shell
gcloud compute backend-services list --project={project} \
  --format="json(name,securityPolicy,protocol,loadBalancingScheme)"
```

### Step 2: Forwarding Rule Inventory
```shell
gcloud compute forwarding-rules list --project={project} \
  --format="json(name,IPProtocol,loadBalancingScheme,portRange,target)"
```
Identify forwarding rules where `loadBalancingScheme` is `EXTERNAL` or
`EXTERNAL_MANAGED` — these are internet-facing.

### Step 3: Security Policy Inventory
```shell
gcloud compute security-policies list --project={project} --format="json(name,type)"
```

### Step 4: Missing WAF Coverage
For each backend service serving an external forwarding rule (Step 2),
flag it if `securityPolicy` is empty/unset — there is no Cloud Armor
policy attached to inspect or rate-limit incoming traffic.

### Step 5: No Security Policies At All
If Step 3 returns zero security policies in a project that has any
external forwarding rule, flag once at project level.

## Severity Guidelines
- HIGH: External-facing backend service with no Cloud Armor policy attached
- MEDIUM: Project has external load balancers but zero security policies
  defined anywhere
- INFO: Security policy exists but has no rules beyond the default
  allow-all rule

## Output Requirements
Return a JSON object matching this structure exactly:
{
  "domain": "load_balancing",
  "projects_audited": ["list of project IDs"],
  "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [<array of AuditFinding objects per schemas/finding.json>]
}
