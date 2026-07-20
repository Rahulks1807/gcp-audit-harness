"""Firewall domain auditor — see skills/firewall_audit.md.

Covers permissive internet-facing ingress rules, missing default-deny
rules per network, and simple shadow-rule (dead rule) detection.
"""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "firewall"

SENSITIVE_PORT_SEVERITY = {
    "22": "critical",
    "3389": "critical",
    "8080": "high",
    "8443": "high",
}
INTERNET_CIDR = "0.0.0.0/0"
DEFAULT_DENY_MIN_PRIORITY = 65534


def _network_name(network_uri: str) -> str:
    return network_uri.rsplit("/", 1)[-1] if network_uri else "default"


def _ports_from_rules(rule_entries: list[dict]) -> set[str]:
    ports: set[str] = set()
    for entry in rule_entries or []:
        if entry.get("IPProtocol") == "all" or not entry.get("ports"):
            ports.add("all")
        else:
            ports.update(entry["ports"])
    return ports


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    rules = await run_gcloud([
        "compute", "firewall-rules", "list", f"--project={project}",
        "--format=json(name,network,direction,priority,sourceRanges,"
        "destinationRanges,allowed,denied,targetTags,targetServiceAccounts,disabled)",
    ]) or []

    rules_by_network: dict[str, list[dict]] = {}
    for rule in rules:
        rules_by_network.setdefault(_network_name(rule.get("network", "")), []).append(rule)

    # Step 2: overly permissive internet-facing ingress rules.
    for rule in rules:
        if rule.get("disabled") or rule.get("direction") != "INGRESS":
            continue
        if INTERNET_CIDR not in (rule.get("sourceRanges") or []):
            continue
        ports = _ports_from_rules(rule.get("allowed"))
        if not ports:
            continue

        if "all" in ports:
            severity = "critical"
        else:
            matched = [SENSITIVE_PORT_SEVERITY[p] for p in ports if p in SENSITIVE_PORT_SEVERITY]
            severity = "critical" if "critical" in matched else ("high" if matched else "medium")

        target_sas = rule.get("targetServiceAccounts") or []
        tags = [f"service-account:{sa}" for sa in target_sas] if target_sas and severity in ("critical", "high") else None

        findings.append(builder.build(
            domain=DOMAIN, severity=severity, project=project,
            resource=rule.get("name", "unknown-rule"),
            detail=f"Ingress rule '{rule.get('name')}' permits {INTERNET_CIDR} on port(s) {', '.join(sorted(ports))}.",
            remediation="Restrict source ranges to known CIDRs, or use IAP tunneling for administrative access.",
            raw_evidence=rule,
            cross_domain_tags=tags,
        ))

    for network, net_rules in rules_by_network.items():
        # Step 3: missing default-deny.
        has_default_deny = any(
            r.get("direction") == "INGRESS"
            and not r.get("disabled")
            and r.get("denied")
            and r.get("priority", 0) >= DEFAULT_DENY_MIN_PRIORITY
            for r in net_rules
        )
        if not has_default_deny:
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=network,
                detail=(
                    f"VPC network '{network}' has no explicit deny-all ingress rule at "
                    f"priority {DEFAULT_DENY_MIN_PRIORITY} or lower."
                ),
                remediation="Add an explicit deny-all ingress rule at the lowest priority.",
            ))

        # Step 4: shadow rule detection — an ALLOW rule made unreachable by a
        # higher-priority (lower number) DENY rule covering the same ports.
        allow_rules = [r for r in net_rules if r.get("allowed") and not r.get("disabled")]
        deny_rules = [r for r in net_rules if r.get("denied") and not r.get("disabled")]
        for allow in allow_rules:
            allow_ports = _ports_from_rules(allow.get("allowed"))
            for deny in deny_rules:
                if deny.get("direction") != allow.get("direction"):
                    continue
                if deny.get("priority", DEFAULT_DENY_MIN_PRIORITY + 1) >= allow.get("priority", 0):
                    continue
                deny_ports = _ports_from_rules(deny.get("denied"))
                if "all" in deny_ports or deny_ports >= allow_ports:
                    findings.append(builder.build(
                        domain=DOMAIN, severity="info", project=project,
                        resource=allow.get("name", "unknown-rule"),
                        detail=(
                            f"Rule '{allow.get('name')}' is shadowed by higher-priority deny rule "
                            f"'{deny.get('name')}' on network '{network}' (dead rule)."
                        ),
                        remediation="Remove the shadowed rule to reduce ruleset confusion and attack surface.",
                    ))
                    break

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
