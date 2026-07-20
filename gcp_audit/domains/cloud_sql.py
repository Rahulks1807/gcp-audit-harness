"""Cloud SQL domain auditor — see skills/cloud_sql_audit.md.

Covers public IP + authorized network exposure, SSL/TLS enforcement, and
backup retention posture.
"""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "cloud_sql"
MIN_BACKUP_RETENTION_DAYS = 7


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    instances = await run_gcloud([
        "sql", "instances", "list", f"--project={project}",
        "--format=json(name,settings.ipConfiguration,settings.backupConfiguration,"
        "databaseVersion,settings.availabilityType)",
    ]) or []

    for instance in instances:
        name = instance.get("name", "unknown-instance")
        settings = instance.get("settings") or {}
        ip_config = settings.get("ipConfiguration") or {}
        backup_config = settings.get("backupConfiguration") or {}

        public_ip = bool(ip_config.get("ipv4Enabled"))
        authorized_networks = [n.get("value") for n in ip_config.get("authorizedNetworks", []) or []]
        ssl_required = bool(ip_config.get("requireSsl")) or ip_config.get("sslMode") in (
            "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "ENCRYPTED_ONLY",
        )

        if public_ip and "0.0.0.0/0" in authorized_networks:
            findings.append(builder.build(
                domain=DOMAIN, severity="critical", project=project,
                resource=name,
                detail="Public IP is enabled with 0.0.0.0/0 in authorized networks.",
                remediation="Remove the 0.0.0.0/0 authorized network and scope to specific CIDRs, or disable public IP.",
                cross_domain_tags=[f"cloud-sql-instance:{name}"],
            ))
        elif public_ip and not ssl_required:
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail="Public IP is enabled without SSL/TLS enforcement.",
                remediation="Require SSL/TLS for all connections, or migrate to Private Services Access.",
                cross_domain_tags=[f"cloud-sql-instance:{name}"],
            ))

        if not backup_config.get("enabled"):
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project,
                resource=name,
                detail="Automated backups are disabled.",
                remediation=f"Enable automated backups with at least a {MIN_BACKUP_RETENTION_DAYS}-day retention window.",
            ))
        else:
            retention = backup_config.get("transactionLogRetentionDays")
            if retention is not None and int(retention) < MIN_BACKUP_RETENTION_DAYS:
                findings.append(builder.build(
                    domain=DOMAIN, severity="medium", project=project,
                    resource=name,
                    detail=(
                        f"Transaction log retention is {retention} day(s), below the "
                        f"{MIN_BACKUP_RETENTION_DAYS}-day baseline."
                    ),
                    remediation=f"Increase backup retention to at least {MIN_BACKUP_RETENTION_DAYS} days.",
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
