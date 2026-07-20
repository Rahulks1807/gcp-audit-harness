"""Cloud Run & Cloud Functions domain auditor — see skills/serverless_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "serverless"
INTERNAL_INGRESS_VALUES = {"internal", "internal-and-cloud-load-balancing"}


async def _audit_cloud_run(project: str, regions: list[str], builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    for region in regions:
        services = await run_gcloud([
            "run", "services", "list", f"--project={project}", f"--region={region}",
            "--format=json(metadata.name,metadata.annotations,status.url)",
        ]) or []

        for service in services:
            name = (service.get("metadata") or {}).get("name")
            if not name:
                continue

            policy = await run_gcloud([
                "run", "services", "get-iam-policy", name, f"--region={region}",
                f"--project={project}", "--format=json",
            ]) or {}
            public_invoker = any(
                "allUsers" in (b.get("members") or [])
                for b in policy.get("bindings", []) or []
                if b.get("role") == "roles/run.invoker"
            )

            annotations = (service.get("metadata") or {}).get("annotations") or {}
            ingress = annotations.get("run.googleapis.com/ingress", "all")

            if public_invoker and ingress not in INTERNAL_INGRESS_VALUES:
                findings.append(builder.build(
                    domain=DOMAIN, severity="high", project=project, region=region,
                    resource=name,
                    detail=f"Cloud Run service '{name}' allows unauthenticated invocation (allUsers has roles/run.invoker).",
                    remediation="Remove the allUsers invoker binding and require IAM authentication, or front it with IAP.",
                ))
            elif ingress not in INTERNAL_INGRESS_VALUES:
                findings.append(builder.build(
                    domain=DOMAIN, severity="medium", project=project, region=region,
                    resource=name,
                    detail=f"Cloud Run service '{name}' ingress allows traffic from 'all' rather than internal-only.",
                    remediation="Restrict ingress to internal-and-cloud-load-balancing unless public access is required.",
                ))

    return findings


async def _audit_cloud_functions(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    functions = await run_gcloud([
        "functions", "list", f"--project={project}", "--v2",
        "--format=json(name,httpsTrigger,ingressSettings)",
    ]) or []

    for function in functions:
        full_name = function.get("name", "")
        name = full_name.rsplit("/", 1)[-1]
        region = full_name.split("/locations/")[-1].split("/")[0] if "/locations/" in full_name else None
        if not name:
            continue

        policy = await run_gcloud([
            "functions", "get-iam-policy", name,
            *( [f"--region={region}"] if region else [] ),
            f"--project={project}", "--format=json",
        ]) or {}
        public_invoker = any(
            "allUsers" in (b.get("members") or [])
            for b in policy.get("bindings", []) or []
            if b.get("role") == "roles/cloudfunctions.invoker"
        )

        ingress = function.get("ingressSettings", "ALLOW_ALL")

        if public_invoker and ingress == "ALLOW_ALL":
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project, region=region,
                resource=name,
                detail=f"Cloud Function '{name}' allows unauthenticated invocation (allUsers has roles/cloudfunctions.invoker).",
                remediation="Remove the allUsers invoker binding and require IAM authentication.",
            ))
        elif ingress == "ALLOW_ALL":
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=region,
                resource=name,
                detail=f"Cloud Function '{name}' ingress setting allows traffic from all sources.",
                remediation="Restrict ingress to internal-only or internal-and-gclb unless public access is required.",
            ))

    return findings


async def _audit_project(project: str, regions: list[str], builder: FindingBuilder) -> list[dict]:
    run_findings, functions_findings = await asyncio.gather(
        _audit_cloud_run(project, regions, builder),
        _audit_cloud_functions(project, builder),
    )
    return run_findings + functions_findings


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
