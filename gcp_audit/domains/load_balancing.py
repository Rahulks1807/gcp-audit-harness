"""Load Balancing & Cloud Armor domain auditor — see skills/load_balancing_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "load_balancing"
EXTERNAL_SCHEMES = {"EXTERNAL", "EXTERNAL_MANAGED"}


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    backend_services = await run_gcloud([
        "compute", "backend-services", "list", f"--project={project}",
        "--format=json(name,securityPolicy,protocol,loadBalancingScheme)",
    ]) or []

    forwarding_rules = await run_gcloud([
        "compute", "forwarding-rules", "list", f"--project={project}",
        "--format=json(name,IPProtocol,loadBalancingScheme,portRange,target)",
    ]) or []

    security_policies = await run_gcloud([
        "compute", "security-policies", "list", f"--project={project}", "--format=json(name,type)",
    ]) or []

    has_external_forwarding = any(
        (rule.get("loadBalancingScheme") or "") in EXTERNAL_SCHEMES for rule in forwarding_rules
    )

    for backend in backend_services:
        name = backend.get("name", "unknown-backend-service")
        scheme = backend.get("loadBalancingScheme") or ""
        if scheme not in EXTERNAL_SCHEMES:
            continue
        if not backend.get("securityPolicy"):
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail=f"External backend service '{name}' has no Cloud Armor security policy attached.",
                remediation="Attach a Cloud Armor security policy to inspect and rate-limit incoming traffic.",
                raw_evidence=backend,
            ))

    if has_external_forwarding and not security_policies:
        findings.append(builder.build(
            domain=DOMAIN, severity="medium", project=project,
            resource=project,
            detail="Project has external-facing load balancers but zero Cloud Armor security policies defined.",
            remediation="Create at least a baseline Cloud Armor policy (e.g. rate limiting, known-bad-IP denylist).",
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
