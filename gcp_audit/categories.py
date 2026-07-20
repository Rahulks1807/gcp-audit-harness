"""Domain -> category grouping, used to keep reports/dashboard readable as
more domains are added. Single source of truth: both the Markdown report
(`gcp_audit/report.py`) and the JSON report's `categories` field (consumed
by the dashboard) are derived from this mapping.
"""

CATEGORY_ORDER = [
    "Networking",
    "Identity & Governance",
    "Compute & Containers",
    "Data, Storage & Messaging",
    "Encryption & Secrets",
]

DOMAIN_CATEGORIES = {
    "networking": "Networking",
    "firewall": "Networking",
    "load_balancing": "Networking",
    "dns": "Networking",
    "iam": "Identity & Governance",
    "org_policy": "Identity & Governance",
    "compute": "Compute & Containers",
    "gke": "Compute & Containers",
    "serverless": "Compute & Containers",
    "artifact_registry": "Compute & Containers",
    "cloud_sql": "Data, Storage & Messaging",
    "storage": "Data, Storage & Messaging",
    "bigquery": "Data, Storage & Messaging",
    "pubsub": "Data, Storage & Messaging",
    "kms_secrets": "Encryption & Secrets",
}

DOMAIN_LABELS = {
    "networking": "Networking",
    "firewall": "Firewall",
    "load_balancing": "Load Balancing",
    "dns": "Cloud DNS",
    "iam": "IAM",
    "org_policy": "Org Policy & Logging",
    "compute": "Compute Engine",
    "gke": "GKE",
    "serverless": "Cloud Run / Functions",
    "artifact_registry": "Artifact Registry",
    "cloud_sql": "Cloud SQL",
    "storage": "Storage",
    "bigquery": "BigQuery",
    "pubsub": "Pub/Sub",
    "kms_secrets": "KMS & Secret Manager",
}


def category_for(domain: str) -> str:
    return DOMAIN_CATEGORIES.get(domain, "Other")


def build_category_summary(domain_results: dict) -> dict:
    """Group per-domain severity_counts into per-category totals, in
    CATEGORY_ORDER, for use by the report/dashboard."""
    summary: dict[str, dict] = {}
    for domain, result in domain_results.items():
        category = category_for(domain)
        bucket = summary.setdefault(category, {"domains": [], "severity_counts": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }})
        bucket["domains"].append(domain)
        for severity, count in result.get("severity_counts", {}).items():
            bucket["severity_counts"][severity] = bucket["severity_counts"].get(severity, 0) + count

    ordered = {c: summary[c] for c in CATEGORY_ORDER if c in summary}
    ordered.update({c: v for c, v in summary.items() if c not in ordered})
    return ordered
