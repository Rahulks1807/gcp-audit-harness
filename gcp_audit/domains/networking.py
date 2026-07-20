"""Networking domain auditor — see skills/networking_audit.md.

Covers NCC hub/spoke inventory and health, CIDR overlap detection across
subnets, and Cloud Router BGP session state.
"""

import asyncio
import ipaddress

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "networking"


async def _audit_project(project: str, regions: list[str], builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    hubs = await run_gcloud([
        "network-connectivity", "hubs", "list",
        f"--project={project}",
        "--format=json(name,state,description)",
    ]) or []
    for hub in hubs:
        if not hub.get("description"):
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=hub.get("name", "unknown-hub"),
                detail="NCC hub is missing a description.",
                remediation="Add a description documenting the hub's purpose and owning team.",
            ))

    spokes = await run_gcloud([
        "network-connectivity", "spokes", "list",
        f"--project={project}",
        "--format=json(name,state,hub,linkedVpnTunnels,"
        "linkedInterconnectAttachments,linkedRouterApplianceInstances)",
    ]) or []
    for spoke in spokes:
        state = spoke.get("state", "UNKNOWN")
        if state == "ACTIVE":
            continue
        severity = "high" if state != "CREATING" else "medium"
        findings.append(builder.build(
            domain=DOMAIN, severity=severity, project=project,
            resource=spoke.get("name", "unknown-spoke"),
            detail=f"Spoke is in state '{state}', expected ACTIVE.",
            remediation="Investigate spoke provisioning/connectivity before relying on this path.",
            raw_evidence=spoke,
        ))

    # CIDR overlap detection across subnets visible to this project.
    subnet_ranges: list[tuple[str, str, ipaddress.IPv4Network]] = []
    for region in regions:
        subnets = await run_gcloud([
            "compute", "networks", "subnets", "list",
            f"--project={project}", f"--filter=region:{region}",
            "--format=json(name,network,ipCidrRange)",
        ]) or []
        for subnet in subnets:
            cidr = subnet.get("ipCidrRange")
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            subnet_ranges.append((subnet.get("name", "unknown-subnet"), region, net))

    for i in range(len(subnet_ranges)):
        name_a, region_a, net_a = subnet_ranges[i]
        for j in range(i + 1, len(subnet_ranges)):
            name_b, region_b, net_b = subnet_ranges[j]
            if net_a.overlaps(net_b):
                findings.append(builder.build(
                    domain=DOMAIN, severity="high", project=project,
                    resource=f"{name_a},{name_b}",
                    detail=(
                        f"Subnet '{name_a}' ({region_a}, {net_a}) overlaps with "
                        f"'{name_b}' ({region_b}, {net_b})."
                    ),
                    remediation="Re-allocate one of the subnets to a non-overlapping CIDR block.",
                ))

    # BGP session health for Cloud Routers in this project.
    for region in regions:
        routers = await run_gcloud([
            "compute", "routers", "list",
            f"--project={project}", f"--filter=region:{region}",
            "--format=json(name)",
        ]) or []
        for router in routers:
            router_name = router.get("name")
            if not router_name:
                continue
            status = await run_gcloud([
                "compute", "routers", "get-status", router_name,
                f"--region={region}", f"--project={project}",
                "--format=json(result.bgpPeerStatus)",
            ])
            peers = ((status or {}).get("result") or {}).get("bgpPeerStatus", []) or []
            for peer in peers:
                if peer.get("state") == "Established":
                    continue
                findings.append(builder.build(
                    domain=DOMAIN, severity="critical", project=project, region=region,
                    resource=f"{router_name}/{peer.get('name', 'unknown-peer')}",
                    detail=(
                        f"BGP session '{peer.get('name')}' on router '{router_name}' is in "
                        f"state '{peer.get('state')}', not Established."
                    ),
                    remediation="Investigate Cloud Router peering and the on-prem/peer router configuration.",
                    raw_evidence=peer,
                ))

    return findings


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
