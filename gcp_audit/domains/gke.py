"""GKE domain auditor — see skills/gke_audit.md.

Covers Binary Authorization enforcement, node auto-upgrade/release channel
posture, and Workload Identity enablement, all derivable from
`gcloud container clusters list`. Per-KSA workload identity binding scope
(skill Step 2) requires in-cluster `kubectl` access and is out of scope for
a `gcloud`-only implementation; clusters with Workload Identity enabled are
still tagged for cross-domain correlation against Cloud SQL/Storage findings.
"""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "gke"


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    clusters = await run_gcloud([
        "container", "clusters", "list", f"--project={project}",
        "--format=json(name,location,binaryAuthorization,workloadIdentityConfig,"
        "nodePools,releaseChannel)",
    ]) or []

    for cluster in clusters:
        name = cluster.get("name", "unknown-cluster")
        location = cluster.get("location")

        eval_mode = (cluster.get("binaryAuthorization") or {}).get("evaluationMode")
        if eval_mode != "PROJECT_SINGLETON_POLICY_ENFORCE":
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project, region=location,
                resource=name,
                detail=f"Binary Authorization is not enforced (evaluationMode={eval_mode!r}).",
                remediation="Enable Binary Authorization with a default attestor policy.",
            ))

        channel = (cluster.get("releaseChannel") or {}).get("channel", "UNSPECIFIED")
        if channel == "UNSPECIFIED":
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=location,
                resource=name,
                detail="Cluster is not enrolled in a release channel.",
                remediation="Enroll the cluster in the Regular or Stable release channel.",
            ))

        for pool in cluster.get("nodePools", []) or []:
            if not (pool.get("management") or {}).get("autoUpgrade", False):
                findings.append(builder.build(
                    domain=DOMAIN, severity="medium", project=project, region=location,
                    resource=f"{name}/{pool.get('name', 'unknown-pool')}",
                    detail="Node pool auto-upgrade is disabled.",
                    remediation="Enable node auto-upgrade to keep pace with security patches.",
                ))

        workload_pool = (cluster.get("workloadIdentityConfig") or {}).get("workloadPool")
        if not workload_pool:
            findings.append(builder.build(
                domain=DOMAIN, severity="medium", project=project, region=location,
                resource=name,
                detail="Workload Identity is not enabled on this cluster.",
                remediation=(
                    "Enable Workload Identity so pods use scoped Google service accounts "
                    "instead of the node's default service account."
                ),
            ))
        else:
            # Enabled clusters are the ones capable of the GKE -> Cloud SQL /
            # Storage cross-domain chain the skill file calls out; tag them so
            # risk_synthesis can attempt the correlation even without
            # in-cluster KSA binding data.
            findings.append(builder.build(
                domain=DOMAIN, severity="info", project=project, region=location,
                resource=name,
                detail="Workload Identity is enabled; verify KSA-to-GSA bindings are namespace-scoped, not project-wide.",
                remediation="Review IAM bindings on the underlying Google service accounts used by workloads in this cluster.",
                cross_domain_tags=[f"gke-workload-identity:{name}"],
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
