import argparse
import asyncio
import json
import os
from datetime import datetime
from pathlib import Path

from antigravity.sdk import AgentHarness, SubAgent, TaskGraph, TokenBudgetMonitor

# Initialise harness with Gemini 3.5 reasoning model
harness = AgentHarness(
    name="gcp-infrastructure-auditor",
    model="gemini-3.5-reasoning",
    max_parallel_subagents=6,
    result_store="shared",  # Domain agents write to shared store
)

# Token budget monitor — prevent runaway costs on large environments
budget = TokenBudgetMonitor(
    max_tokens_per_turn=8000,
    max_cumulative_tokens=50000,
    on_exceed="warn"  # Use "kill" in production for hard stops
)

# Default audit domains. All six run in parallel; cross-domain chains
# (e.g. GKE workload identity -> Cloud SQL exposure) are only detected
# when both relevant domains are included in the same run.
DEFAULT_DOMAINS = ["networking", "iam", "firewall", "gke", "cloud_sql", "storage"]


@harness.orchestrate
def build_audit_graph(scope: dict) -> TaskGraph:
    """
    Builds the task dependency graph for the audit.
    Domain agents run in parallel; synthesis waits for all domains.
    """
    graph = TaskGraph()

    audit_domains = scope.get("audit_domains", DEFAULT_DOMAINS)

    for domain in audit_domains:
        graph.add_task(
            task_id=f"audit_{domain}",
            agent=SubAgent(
                name=f"{domain}-auditor",
                skill=f"skills/{domain}_audit.md",
                context={
                    "projects": scope["projects"],
                    "regions": scope.get("regions", ["us-central1"]),
                    "schema_path": "schemas/finding.json"
                },
                timeout_seconds=300,
                token_budget=budget,
            ),
            # Domain agents run in parallel — no dependencies between them
        )

    # Synthesis waits for ALL domain agents to complete
    graph.add_task(
        task_id="synthesize_findings",
        agent=SubAgent(
            name="risk-synthesizer",
            skill="skills/risk_synthesis.md",
            context_from_tasks=[f"audit_{d}" for d in audit_domains],
            timeout_seconds=120,
        ),
        depends_on=[f"audit_{d}" for d in audit_domains],
    )

    return graph


async def run_audit(config_path: str = "audit_config.json") -> dict:
    """Main audit runner."""
    with open(config_path) as f:
        scope = json.load(f)

    audit_domains = scope.get("audit_domains", DEFAULT_DOMAINS)

    print(f"[{datetime.now().isoformat()}] Starting audit for {len(scope['projects'])} projects")
    print(f"Domains: {audit_domains}")
    print(f"Regions: {scope.get('regions', ['us-central1'])}")
    print("-" * 60)

    start_time = datetime.now()
    result = await harness.run(scope)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Save the full report
    report_dir = Path(scope.get("output_dir", "reports"))
    report_dir.mkdir(exist_ok=True)
    report_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"audit_report_{report_date}.json"

    # Augment the output with run metadata — this is what the dashboard
    # reads for its header (projects audited, duration, domains covered)
    output = result.output
    output["metadata"] = {
        "projects_audited": scope["projects"],
        "audit_domains": audit_domains,
        "duration_seconds": round(elapsed, 1),
        "timestamp": datetime.now().isoformat()
    }

    with open(report_path, "w") as f:
        json.dump(output, f, indent=2)

    # Also save a human-readable markdown summary
    md_path = report_dir / f"audit_report_{report_date}.md"
    write_markdown_report(output, md_path, elapsed)

    print(f"\n[{datetime.now().isoformat()}] Audit complete in {elapsed:.1f}s")
    print(f"Report saved: {report_path}")
    print(f"Summary saved: {md_path}")
    print("\n--- Executive Summary ---")
    print(output.get("executive_summary", "No summary generated"))

    return output


def write_markdown_report(output: dict, path: Path, elapsed: float):
    """Write a human-readable markdown report."""
    lines = [
        f"# GCP Infrastructure Audit Report",
        f"*Generated: {datetime.now().isoformat()} | Duration: {elapsed:.1f}s*",
        "",
        "## Executive Summary",
        "",
        output.get("executive_summary", ""),
        "",
        "## Metrics",
        "",
    ]

    metrics = output.get("metrics", {})
    lines += [
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Findings | {metrics.get('total_findings', 0)} |",
        f"| Risk Chains Identified | {metrics.get('risk_chains_identified', 0)} |",
        f"| Critical | {metrics.get('critical_count', 0)} |",
        f"| High | {metrics.get('high_count', 0)} |",
        "",
        "## Risk Chains",
        "",
    ]

    for chain in output.get("risk_chains", []):
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(
            chain["severity"], "⚪"
        )
        lines += [
            f"### {severity_emoji} {chain['chain_id']} — {chain['severity'].upper()}",
            "",
            f"**Findings involved:** {', '.join(chain['finding_ids'])}",
            "",
            chain["description"],
            "",
            f"**Blast radius:** {chain['blast_radius']}",
            "",
            "**Remediation steps:**",
        ]
        for step in chain.get("remediation_steps", []):
            lines.append(f"- {step}")
        lines.append("")

    lines += [
        "## Prioritised Remediation Plan",
        "",
        "| Priority | Finding/Chain | Severity | Effort | Impact |",
        "|----------|--------------|----------|--------|--------|",
    ]

    for i, item in enumerate(output.get("remediation_plan", []), 1):
        lines.append(
            f"| {i} | {item.get('id', '')} | {item.get('severity', '')} | "
            f"{item.get('effort', '')} | {item.get('impact', '')} |"
        )

    with open(path, "w") as f:
        f.write("\n".join(lines))


def parse_args():
    parser = argparse.ArgumentParser(description="Run the multi-agent GCP infrastructure audit.")
    parser.add_argument(
        "--config",
        default="audit_config.json",
        help="Path to the audit configuration JSON file (default: audit_config.json)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run_audit(config_path=args.config))
