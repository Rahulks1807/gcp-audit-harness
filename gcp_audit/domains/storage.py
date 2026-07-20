"""Cloud Storage domain auditor — see skills/storage_audit.md.

Covers public IAM bindings (allUsers/allAuthenticatedUsers), uniform
bucket-level access, public access prevention, and label/governance gaps.
"""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "storage"
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    buckets = await run_gcloud([
        "storage", "buckets", "list", f"--project={project}",
        "--format=json(name,iamConfiguration.uniformBucketLevelAccess,"
        "iamConfiguration.publicAccessPrevention,labels)",
    ]) or []

    for bucket in buckets:
        name = bucket.get("name", "unknown-bucket")
        labels = bucket.get("labels") or {}
        is_pii = labels.get("data-classification", "").lower() == "pii"
        iam_config = bucket.get("iamConfiguration") or {}
        uniform_access = bool((iam_config.get("uniformBucketLevelAccess") or {}).get("enabled"))
        pap = iam_config.get("publicAccessPrevention")

        policy = await run_gcloud([
            "storage", "buckets", "get-iam-policy", f"gs://{name}", "--format=json",
        ]) or {}
        public_bindings = [
            b for b in (policy.get("bindings") or [])
            if PUBLIC_MEMBERS & set(b.get("members", []))
        ]

        if public_bindings:
            severity = "critical" if is_pii else "high"
            roles = ", ".join(b.get("role", "unknown") for b in public_bindings)
            findings.append(builder.build(
                domain=DOMAIN, severity=severity, project=project,
                resource=name,
                detail=f"Bucket IAM policy grants public access ({roles}) to allUsers/allAuthenticatedUsers.",
                remediation="Remove the public IAM binding; use signed URLs or IAP for controlled access instead.",
                raw_evidence={"bindings": public_bindings},
                cross_domain_tags=[f"bucket:{name}"],
            ))

        if not uniform_access:
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=name,
                detail="Uniform bucket-level access is disabled; legacy ACLs may grant unaudited access.",
                remediation="Enable uniform bucket-level access and audit/remove any legacy ACLs.",
            ))

        if is_pii and pap != "enforced":
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail="Public access prevention is not 'enforced' on a bucket labelled as holding PII.",
                remediation="Set publicAccessPrevention to 'enforced' on this bucket.",
            ))

        if not labels:
            findings.append(builder.build(
                domain=DOMAIN, severity="info", project=project,
                resource=name,
                detail="Bucket has no labels (governance gap, not a direct security risk).",
                remediation="Add labels documenting the owning team and data classification.",
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
