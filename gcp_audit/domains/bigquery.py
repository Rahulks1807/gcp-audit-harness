"""BigQuery domain auditor — see skills/bigquery_audit.md.

Uses the `bq` CLI (bundled with the Cloud SDK) rather than `gcloud`, since
dataset-level access control isn't exposed through `gcloud` commands.
"""

import asyncio

from ..gcloud_client import run_bq
from ..models import FindingBuilder

DOMAIN = "bigquery"
PUBLIC_SPECIAL_GROUPS = {"allAuthenticatedUsers"}


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    datasets = await run_bq([
        "ls", "--format=prettyjson", "--max_results=1000", f"--project_id={project}",
    ]) or []

    for dataset in datasets:
        dataset_id = (dataset.get("datasetReference") or {}).get("datasetId")
        if not dataset_id:
            continue

        details = await run_bq([
            "show", "--format=prettyjson", f"{project}:{dataset_id}",
        ]) or {}

        labels = details.get("labels") or {}
        is_pii = labels.get("data-classification", "").lower() == "pii"

        public_entries = [
            entry for entry in details.get("access", []) or []
            if entry.get("specialGroup") in PUBLIC_SPECIAL_GROUPS
            or entry.get("iamMember") in ("allUsers", "allAuthenticatedUsers")
            or entry.get("userByEmail") in ("allUsers", "allAuthenticatedUsers")
        ]
        if public_entries:
            roles = ", ".join(sorted({e.get("role", "unknown") for e in public_entries}))
            findings.append(builder.build(
                domain=DOMAIN, severity="critical", project=project,
                resource=dataset_id,
                detail=f"Dataset access list grants '{roles}' to allUsers/allAuthenticatedUsers.",
                remediation="Remove the public access entry; grant access to specific principals instead.",
                raw_evidence={"access": public_entries},
            ))

        if is_pii and not (details.get("defaultEncryptionConfiguration") or {}).get("kmsKeyName"):
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=dataset_id,
                detail="Dataset labelled 'pii' has no customer-managed encryption key (CMEK) configured.",
                remediation="Configure a default CMEK key for this dataset.",
            ))

        if not labels:
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=dataset_id,
                detail="Dataset has no labels documenting owner or data classification.",
                remediation="Add labels for the owning team and data classification.",
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
