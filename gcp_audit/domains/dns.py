"""Cloud DNS domain auditor — see skills/dns_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "dns"
INTERNAL_NAME_HINTS = ("internal", "corp", "staging", "private")


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    zones = await run_gcloud([
        "dns", "managed-zones", "list", f"--project={project}",
        "--format=json(name,dnsName,visibility,dnssecConfig)",
    ]) or []

    for zone in zones:
        name = zone.get("name", "unknown-zone")
        dns_name = zone.get("dnsName", "")
        visibility = zone.get("visibility", "public")

        if visibility != "public":
            continue

        dnssec_state = (zone.get("dnssecConfig") or {}).get("state", "off")
        if dnssec_state != "on":
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail=f"Public zone '{dns_name}' does not have DNSSEC enabled (state={dnssec_state!r}).",
                remediation="Enable DNSSEC on this managed zone to protect against cache poisoning/spoofing.",
            ))

        haystack = f"{name} {dns_name}".lower()
        if any(hint in haystack for hint in INTERNAL_NAME_HINTS):
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=name,
                detail=f"Zone '{dns_name}' is public but its name suggests it may be intended as internal-only.",
                remediation="Verify this zone's visibility is intentional; switch to a private zone if not.",
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
