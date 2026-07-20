"""Org Policy & Logging domain auditor — see skills/org_policy_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "org_policy"

RECOMMENDED_CONSTRAINTS = {
    "constraints/iam.disableServiceAccountKeyCreation": "User-managed service account keys can still be created.",
    "constraints/compute.requireOsLogin": "OS Login is not required project-wide for Compute Engine.",
    "constraints/compute.vmExternalIpAccess": "VM external IP access is not restricted by an allowlist.",
    "constraints/storage.uniformBucketLevelAccess": "Uniform bucket-level access is not enforced project-wide.",
    "constraints/sql.restrictPublicIp": "Cloud SQL public IP is not restricted project-wide.",
}


async def _audit_org_policies(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    policies = await run_gcloud([
        "resource-manager", "org-policies", "list", f"--project={project}", "--format=json",
    ])
    if policies is None:
        return findings

    configured_constraints = {p.get("constraint") for p in policies}

    for constraint, description in RECOMMENDED_CONSTRAINTS.items():
        if constraint in configured_constraints:
            continue
        findings.append(builder.build(
            domain=DOMAIN, severity="medium", project=project,
            resource=constraint,
            detail=f"Recommended org policy constraint is not set at the project level. {description}",
            remediation=f"Set '{constraint}' at the project, folder, or org level, whichever is appropriate.",
        ))

    return findings


async def _audit_logging(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    sinks = await run_gcloud([
        "logging", "sinks", "list", f"--project={project}", "--format=json(name,destination,filter)",
    ])
    settings = await run_gcloud([
        "logging", "settings", "describe", f"--project={project}", "--format=json",
    ]) or {}

    has_sinks = bool(sinks)
    default_sink_disabled = bool(settings.get("disableDefaultSink"))

    if default_sink_disabled and not has_sinks:
        findings.append(builder.build(
            domain=DOMAIN, severity="high", project=project,
            resource=project,
            detail="The default log sink is disabled and no replacement sink is configured — audit logs may not be retained.",
            remediation="Configure at least one log sink (e.g. to BigQuery or Cloud Storage) before disabling the default sink.",
        ))
    elif not has_sinks:
        findings.append(builder.build(
            domain=DOMAIN, severity="medium", project=project,
            resource=project,
            detail="No log sinks are configured; audit logs only persist for the default Cloud Logging retention window.",
            remediation="Add a log sink exporting to BigQuery/Cloud Storage/Pub/Sub for durable, longer-term retention.",
        ))

    return findings


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    org_findings, logging_findings = await asyncio.gather(
        _audit_org_policies(project, builder),
        _audit_logging(project, builder),
    )
    return org_findings + logging_findings


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
