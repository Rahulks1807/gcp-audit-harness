# Firewall Audit Skill

## Objective
Audit VPC firewall rules and hierarchical firewall policies for overly
permissive configurations, shadow rules, and missing deny-all defaults.

## Tools Available
- shell: Execute gcloud CLI commands

## Execution Steps

### Step 1: Firewall Rule Export
```shell
gcloud compute firewall-rules list \
  --project={project} \
  --format="json(name,network,direction,priority,sourceRanges,destinationRanges,\
allowed,denied,targetTags,targetServiceAccounts,disabled)"
```

### Step 2: Overly Permissive Ingress Rules
Flag rules where:
- direction=INGRESS AND sourceRanges contains "0.0.0.0/0"
- AND allowed ports include: 22 (SSH), 3389 (RDP), 8080, 8443, or "all"

Severity:
- CRITICAL: 0.0.0.0/0 on SSH/RDP
- HIGH: 0.0.0.0/0 on application ports (8080, 8443)
- MEDIUM: 0.0.0.0/0 on non-standard ports

### Step 3: Missing Default Deny
Check each VPC network for the presence of a deny-all ingress rule with
priority 65534 or lower. Flag absence as MEDIUM.

### Step 4: Shadow Rule Detection
For each ALLOW rule, check whether a higher-priority DENY rule on the same
network and port range makes it unreachable. Flag as INFO (dead rules
increase attack surface by creating confusion).

### Step 5: Target Service Account Correlation
For any HIGH/CRITICAL finding, if the rule uses targetServiceAccounts,
add cross_domain_tags: ["service-account:{sa_email}"]
This enables cross-domain correlation with IAM findings.

## Output Requirements
Return JSON matching schemas/finding.json for each finding.
