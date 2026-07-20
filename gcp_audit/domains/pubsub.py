"""Pub/Sub domain auditor — see skills/pubsub_audit.md."""

import asyncio

from ..gcloud_client import run_gcloud
from ..models import FindingBuilder

DOMAIN = "pubsub"
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


async def _audit_topics(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    topics = await run_gcloud([
        "pubsub", "topics", "list", f"--project={project}", "--format=json(name)",
    ]) or []

    for topic in topics:
        name = (topic.get("name") or "").rsplit("/", 1)[-1]
        if not name:
            continue

        policy = await run_gcloud([
            "pubsub", "topics", "get-iam-policy", name, f"--project={project}", "--format=json",
        ]) or {}
        public_bindings = [
            b for b in policy.get("bindings", []) or []
            if PUBLIC_MEMBERS & set(b.get("members", []))
        ]
        if public_bindings:
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail=f"Topic IAM policy grants public access: {', '.join(b.get('role', '') for b in public_bindings)}.",
                remediation="Remove the public binding; grant publisher/subscriber roles to specific principals.",
                raw_evidence={"bindings": public_bindings},
            ))

    return findings


async def _audit_subscriptions(project: str, builder: FindingBuilder) -> list[dict]:
    findings: list[dict] = []

    subscriptions = await run_gcloud([
        "pubsub", "subscriptions", "list", f"--project={project}",
        "--format=json(name,topic,ackDeadlineSeconds,expirationPolicy)",
    ]) or []

    for sub in subscriptions:
        name = (sub.get("name") or "").rsplit("/", 1)[-1]
        if not name:
            continue

        policy = await run_gcloud([
            "pubsub", "subscriptions", "get-iam-policy", name, f"--project={project}", "--format=json",
        ]) or {}
        public_bindings = [
            b for b in policy.get("bindings", []) or []
            if PUBLIC_MEMBERS & set(b.get("members", []))
        ]
        if public_bindings:
            findings.append(builder.build(
                domain=DOMAIN, severity="high", project=project,
                resource=name,
                detail=f"Subscription IAM policy grants public access: {', '.join(b.get('role', '') for b in public_bindings)}.",
                remediation="Remove the public binding; grant subscriber role to specific principals.",
                raw_evidence={"bindings": public_bindings},
            ))

        expiration = sub.get("expirationPolicy")
        if expiration is not None and not expiration.get("ttl"):
            findings.append(builder.build(
                domain=DOMAIN, severity="info", project=project,
                resource=name,
                detail="Subscription has no expiration policy TTL set (never expires).",
                remediation="Confirm this subscription is still in active use, or set an expiration TTL.",
            ))

    return findings


async def _audit_project(project: str, builder: FindingBuilder) -> list[dict]:
    topic_findings, sub_findings = await asyncio.gather(
        _audit_topics(project, builder),
        _audit_subscriptions(project, builder),
    )
    return topic_findings + sub_findings


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
