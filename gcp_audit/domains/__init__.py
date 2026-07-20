"""Domain auditor implementations, one module per `skills/*_audit.md` file.

Each module exposes `async def audit(projects: list[str], regions: list[str]) -> dict`
returning `{"domain", "projects_audited", "severity_counts", "findings"}`.

`DOMAIN_MODULES` order below also drives the default `audit_domains` order
and roughly groups related services together (see `gcp_audit/categories.py`
for the category each domain belongs to in reports/the dashboard).
"""

from . import (
    artifact_registry,
    bigquery,
    cloud_sql,
    compute,
    dns,
    firewall,
    gke,
    iam,
    kms_secrets,
    load_balancing,
    networking,
    org_policy,
    pubsub,
    serverless,
    storage,
)

DOMAIN_MODULES = {
    "networking": networking,
    "firewall": firewall,
    "load_balancing": load_balancing,
    "dns": dns,
    "iam": iam,
    "org_policy": org_policy,
    "compute": compute,
    "gke": gke,
    "serverless": serverless,
    "artifact_registry": artifact_registry,
    "cloud_sql": cloud_sql,
    "storage": storage,
    "bigquery": bigquery,
    "pubsub": pubsub,
    "kms_secrets": kms_secrets,
}
