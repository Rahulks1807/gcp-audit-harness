"""IAM domain auditor — see skills/iam_audit.md.

Covers overprivileged project-level bindings, stale user-managed service
account keys, and PAM entitlement coverage for the privileged roles found.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "iam"

OVERPRIVILEGED_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityAdmin"}
USER_SCOPED_ROLES = {"roles/compute.networkAdmin"}
KEY_AGE_THRESHOLD_DAYS = 90


def _parse_time(value: Optional[str]):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    policy = await run_gcloud([
        "projects", "get-iam-policy", project, "--format=json",
    ]) or {}
    bindings = policy.get("bindings", []) or []

    # Track which service accounts were flagged for a privileged role, so we
    # can check PAM coverage for exactly those (role, service account) pairs.
    flagged_sa_roles: dict[str, set[str]] = {}

    for binding in bindings:
        role = binding.get("role")
        members = binding.get("members", []) or []

        if role in USER_SCOPED_ROLES:
            offenders = [m for m in members if m.startswith("user:")]
        elif role in OVERPRIVILEGED_ROLES:
            offenders = members
        else:
            continue

        for member in offenders:
            tags = None
            if member.startswith("serviceAccount:"):
                email = member.split(":", 1)[1]
                tags = [f"service-account:{email}"]
                flagged_sa_roles.setdefault(email, set()).add(role)

            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=member,
                detail=f"'{member}' holds '{role}' at project level.",
                remediation=f"Downscope '{member}' to the minimum roles required instead of '{role}'.",
                cross_domain_tags=tags,
            ))

    service_accounts = await run_gcloud([
        "iam", "service-accounts", "list",
        f"--project={project}", "--format=json(email,disabled)",
    ]) or []

    now = datetime.now(timezone.utc)
    for sa in service_accounts:
        email = sa.get("email")
        if not email or sa.get("disabled"):
            continue
        keys = await run_gcloud([
            "iam", "service-accounts", "keys", "list",
            f"--iam-account={email}", "--managed-by=user",
            "--format=json(name,validAfterTime,validBeforeTime)",
        ]) or []
        for key in keys:
            created = _parse_time(key.get("validAfterTime"))
            if not created:
                continue
            age_days = (now - created).days
            if age_days >= KEY_AGE_THRESHOLD_DAYS:
                findings.append(builder.build(
                    domain=DOMAIN, severity="high", project=project,
                    resource=email,
                    detail=(
                        f"User-managed key is {age_days} days old "
                        f"(threshold: {KEY_AGE_THRESHOLD_DAYS} days)."
                    ),
                    remediation="Rotate the key and migrate to Workload Identity Federation where possible.",
                    cross_domain_tags=[f"service-account:{email}"],
                ))

    # PAM entitlement coverage for the privileged roles flagged above.
    entitlements = await run_gcloud([
        "pam", "entitlements", "list",
        "--location=global", f"--project={project}",
        "--format=json(name,privilegedAccess,maxRequestDuration,eligibleUsers)",
    ])
    covered_roles: set[str] = set()
    if entitlements:
        for entitlement in entitlements:
            access = entitlement.get("privilegedAccess") or {}
            role = (access.get("gcpIamAccess") or {}).get("role")
            if role:
                covered_roles.add(role)

    for email, roles in flagged_sa_roles.items():
        for role in roles:
            if role in covered_roles:
                continue
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=email,
                detail=f"'{role}' binding on '{email}' has no PAM entitlement coverage.",
                remediation=f"Wrap '{role}' in a PAM entitlement with a short max request duration.",
                cross_domain_tags=[f"service-account:{email}"],
            ))

    return findings


async def audit(projects: list[str], regions: list[str]) -> dict:
    builder = FindingBuilder(DOMAIN)
    results = await asyncio.gather(*(_audit_project(p, builder) for p in projects))
    findings = [f for group in results for f in group]
    return {
        "domain": DOMAIN,
        "projects_audited": projects,
        "severity_counts": builder.severity_counts(findings),
        "findings": findings,
    }
