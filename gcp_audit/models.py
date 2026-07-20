"""Shared finding-construction helpers.

Keeps every domain auditor's output honestly conformant to
`schemas/finding.json` without repeating ID generation and severity-tallying
boilerplate in each domain module.
"""

from itertools import count
from typing import Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")

_ID_PREFIXES = {
    "networking": "NET",
    "iam": "IAM",
    "firewall": "FW",
    "gke": "GKE",
    "cloud_sql": "SQL",
    "storage": "GCS",
    "compute": "VM",
    "kms_secrets": "KMS",
    "bigquery": "BQ",
    "pubsub": "PS",
    "serverless": "SRV",
    "load_balancing": "LB",
    "dns": "DNS",
    "artifact_registry": "AR",
    "org_policy": "ORG",
}


class FindingBuilder:
    """Generates schema-conformant findings with sequential per-domain IDs."""

    def __init__(self, domain: str):
        self.domain = domain
        self._prefix = _ID_PREFIXES.get(domain, domain.upper()[:3])
        self._counter = count(1)

    def build(
        self,
        *,
        domain: str,
        severity: str,
        project: str,
        resource: str,
        detail: str,
        remediation: str,
        region: Optional[str] = None,
        raw_evidence: Optional[dict] = None,
        cross_domain_tags: Optional[list[str]] = None,
    ) -> dict:
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}', must be one of {SEVERITIES}")

        finding = {
            "id": f"{self._prefix}-{next(self._counter):03d}",
            "domain": domain,
            "severity": severity,
            "resource": resource,
            "project": project,
            "detail": detail,
            "remediation": remediation,
        }
        if region:
            finding["region"] = region
        if raw_evidence is not None:
            finding["raw_evidence"] = raw_evidence
        if cross_domain_tags:
            finding["cross_domain_tags"] = cross_domain_tags
        return finding

    @staticmethod
    def severity_counts(findings: list[dict]) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        return counts
