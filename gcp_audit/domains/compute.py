"""Compute Engine domain auditor — see skills/compute_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "compute"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    instances = await run_gcloud([
        "compute", "instances", "list", f"--project={project}",
        "--format=json(name,zone,networkInterfaces,serviceAccounts,"
        "shieldedInstanceConfig,metadata)",
    ]) or []

    for instance in instances:
        name = instance.get("name", "unknown-instance")
        zone = (instance.get("zone") or "").rsplit("/", 1)[-1]

        has_public_ip = any(
            ac.get("natIP")
            for ni in instance.get("networkInterfaces", []) or []
            for ac in ni.get("accessConfigs", []) or []
        )

        default_sa_full_scope = any(
            sa.get("email", "").endswith("-compute@developer.gserviceaccount.com")
            and CLOUD_PLATFORM_SCOPE in (sa.get("scopes") or [])
            for sa in instance.get("serviceAccounts", []) or []
        )

        if has_public_ip and default_sa_full_scope:
            findings.append(builder.build(
                domain=DOMAIN, severity="critical", project=project, region=zone,
                resource=name,
                detail="Instance has a public IP and uses the default Compute SA with full cloud-platform scope.",
                remediation="Remove the public IP or attach a scoped custom service account instead of the default one.",
                cross_domain_tags=["service-account:default-compute"],
            ))
        elif default_sa_full_scope:
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project, region=zone,
                resource=name,
                detail="Instance uses the default Compute SA with full cloud-platform scope.",
                remediation="Attach a custom service account scoped to only the roles this instance needs.",
                cross_domain_tags=["service-account:default-compute"],
            ))
        elif has_public_ip:
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=zone,
                resource=name,
                detail="Instance has a public IP address.",
                remediation="Remove the external IP and access the instance via IAP tunneling or a bastion host.",
            ))

        metadata_items = {i.get("key"): i.get("value") for i in (instance.get("metadata") or {}).get("items", []) or []}
        if str(metadata_items.get("enable-oslogin", "")).upper() != "TRUE":
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=zone,
                resource=name,
                detail="OS Login is not enabled on this instance.",
                remediation="Enable OS Login for centralized SSH key management and 2FA support.",
            ))
        if str(metadata_items.get("serial-port-enable", "")).upper() == "TRUE":
            findings.append(builder.build(
                domain=DOMAIN, severity="low", project=project, region=zone,
                resource=name,
                detail="Serial port access is enabled.",
                remediation="Disable serial port access unless actively required for debugging.",
            ))

        shielded = instance.get("shieldedInstanceConfig") or {}
        if not all([
            shielded.get("enableSecureBoot", True),
            shielded.get("enableVtpm", True),
            shielded.get("enableIntegrityMonitoring", True),
        ]):
            findings.append(builder.build(
                domain=DOMAIN, severity="low", project=project, region=zone,
                resource=name,
                detail="One or more Shielded VM features (Secure Boot, vTPM, Integrity Monitoring) is disabled.",
                remediation="Enable all Shielded VM options to protect against boot- and firmware-level attacks.",
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
