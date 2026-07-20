"""Artifact Registry domain auditor — see skills/artifact_registry_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "artifact_registry"
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
WRITE_ROLES = {"roles/artifactregistry.writer", "roles/artifactregistry.repoAdmin"}


def _parse_repo_path(full_name: str) -> tuple[str, str]:
    # projects/{project}/locations/{location}/repositories/{repo}
    parts = full_name.split("/")
    try:
        location = parts[parts.index("locations") + 1]
        repo = parts[parts.index("repositories") + 1]
    except (ValueError, IndexError):
        return "", ""
    return location, repo


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    repositories = await run_gcloud([
        "artifacts", "repositories", "list", f"--project={project}",
        "--format=json(name,format,mode,createTime)",
    ]) or []

    for repo in repositories:
        full_name = repo.get("name", "")
        location, repo_id = _parse_repo_path(full_name)
        if not repo_id:
            continue

        policy = await run_gcloud([
            "artifacts", "repositories", "get-iam-policy", repo_id,
            f"--location={location}", f"--project={project}", "--format=json",
        ]) or {}
        public_bindings = [
            b for b in policy.get("bindings", []) or []
            if PUBLIC_MEMBERS & set(b.get("members", []))
        ]

        if public_bindings:
            has_write = any(b.get("role") in WRITE_ROLES for b in public_bindings)
            severity = "critical" if has_write else "high"
            roles = ", ".join(b.get("role", "") for b in public_bindings)
            findings.append(builder.build(
                domain=DOMAIN, severity=severity, project=project, region=location,
                resource=repo_id,
                detail=f"Repository IAM policy grants public access: {roles}.",
                remediation="Remove the public binding; scope repository access to specific principals.",
                raw_evidence={"bindings": public_bindings},
            ))

        if repo.get("mode") == "REMOTE_REPOSITORY":
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=location,
                resource=repo_id,
                detail="Repository proxies an upstream remote registry.",
                remediation="Confirm the upstream is trusted and consider an allowlist for proxied packages.",
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
