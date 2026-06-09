# IAM Audit Skill

## Objective
Audit IAM posture with focus on PAM justification coverage, privilege
accumulation, and service account hygiene across specified GCP projects.

## Tools Available
- shell: Execute gcloud CLI commands
- python: Run Python for policy analysis

## Execution Steps

### Step 1: Project IAM Policy Export
```shell
gcloud projects get-iam-policy {project} --format=json
```

### Step 2: Identify Overprivileged Bindings
Flag these role patterns at project or org level:
- roles/owner
- roles/editor
- roles/iam.securityAdmin
- roles/compute.networkAdmin (when bound to user accounts, not service accounts)

### Step 3: Service Account Key Audit
```shell
gcloud iam service-accounts list --project={project} --format="json(email,disabled)"

# For each service account:
gcloud iam service-accounts keys list \
  --iam-account={sa_email} \
  --managed-by=user \
  --format="json(name,validAfterTime,validBeforeTime)"
```
Flag user-managed keys older than 90 days as HIGH severity.

### Step 4: PAM Entitlement Coverage Check
```shell
gcloud privilegedaccessmanager entitlements list \
  --location=global \
  --project={project} \
  --format="json(name,privilegedAccess,maxRequestDuration,eligibleUsers)"
```
For each HIGH-privilege role binding found in Step 2, check whether a PAM
entitlement exists covering that role. Missing PAM coverage = HIGH finding.
Add cross_domain_tags with the service account email for correlation.

## Output Requirements
Return JSON matching schemas/finding.json for each finding.
Always populate cross_domain_tags with "service-account:{email}" for SA findings.
