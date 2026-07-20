"""KMS & Secret Manager domain auditor — see skills/kms_secrets_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "kms_secrets"
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


async def _audit_kms(project: str, regions: list[str], builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []
    locations = list(dict.fromkeys([*regions, "global"]))

    for location in locations:
        keyrings = await run_gcloud([
            "kms", "keyrings", "list", f"--project={project}", f"--location={location}",
            "--format=json(name)",
        ]) or []

        for keyring in keyrings:
            keyring_name = (keyring.get("name") or "").rsplit("/", 1)[-1]
            if not keyring_name:
                continue

            keys = await run_gcloud([
                "kms", "keys", "list", f"--keyring={keyring_name}", f"--location={location}",
                f"--project={project}", "--format=json(name,rotationPeriod,primary.state)",
            ]) or []

            for key in keys:
                key_name = (key.get("name") or "").rsplit("/", 1)[-1]

                if not key.get("rotationPeriod"):
                    findings.append(builder.build(
                        domain=DOMAIN, severity="high", project=project, region=location,
                        resource=f"{keyring_name}/{key_name}",
                        detail="KMS key has no rotation period configured.",
                        remediation="Configure automatic key rotation (e.g. every 90 days).",
                    ))

                policy = await run_gcloud([
                    "kms", "keys", "get-iam-policy", key_name,
                    f"--keyring={keyring_name}", f"--location={location}",
                    f"--project={project}", "--format=json",
                ]) or {}
                public_bindings = [
                    b for b in policy.get("bindings", []) or []
                    if PUBLIC_MEMBERS & set(b.get("members", []))
                ]
                if public_bindings:
                    findings.append(builder.build(
                        domain=DOMAIN, severity="critical", project=project, region=location,
                        resource=f"{keyring_name}/{key_name}",
                        detail=f"KMS key IAM policy grants public access: {', '.join(b.get('role', '') for b in public_bindings)}.",
                        remediation="Remove the public binding; scope key access to specific service accounts.",
                        raw_evidence={"bindings": public_bindings},
                    ))

    return findings


async def _audit_secret_manager(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    secrets = await run_gcloud([
        "secrets", "list", f"--project={project}", "--format=json(name,createTime,replication)",
    ]) or []

    for secret in secrets:
        name = (secret.get("name") or "").rsplit("/", 1)[-1]
        if not name:
            continue

        policy = await run_gcloud([
            "secrets", "get-iam-policy", name, f"--project={project}", "--format=json",
        ]) or {}
        public_bindings = [
            b for b in policy.get("bindings", []) or []
            if PUBLIC_MEMBERS & set(b.get("members", []))
        ]
        if public_bindings:
            findings.append(builder.build(
                domain=DOMAIN, severity="critical", project=project,
                resource=name,
                detail=f"Secret IAM policy grants public access: {', '.join(b.get('role', '') for b in public_bindings)}.",
                remediation="Remove the public binding; scope secret access to specific service accounts.",
                raw_evidence={"bindings": public_bindings},
            ))

    return findings


async def _audit_project(project: str, regions: list[str], builder: FindingBuilder) -> list[dict]:
    kms_findings, secret_findings = await asyncio.gather(
        _audit_kms(project, regions, builder),
        _audit_secret_manager(project, builder),
    )
    return kms_findings + secret_findings


async def audit(projects: list[str], regions: list[str]) -> dict:
    builder = FindingBuilder(DOMAIN)
    results = await asyncio.gather(*(_audit_project(p, regions, builder) for p in projects))
    findings = [f for group in results for f in group]
    return {
        "domain": DOMAIN,
        "projects_audited": projects,
        "severity_counts": builder.severity_counts(findings),
        "findings": findings,
    }
