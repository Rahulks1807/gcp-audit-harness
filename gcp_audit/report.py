"""Markdown report rendering for a completed audit run.

With 15 domains in play, a single flat findings table gets unreadable
fast. This renders:
  1. Executive summary + top-line metrics (always visible)
  2. Risk chains (always visible — these are the headline items)
  3. A flat "Critical & High" table (always visible — the stuff to act on today)
  4. The prioritised remediation plan (always visible)
  5. Full findings, grouped by category then domain, using GitHub-flavoured
     `<details>` blocks so each section collapses to just a severity-count
     summary line until expanded.
"""

from datetime import datetime
from pathlib import Path

from .categories import CATEGORY_ORDER, DOMAIN_LABELS, build_category_summary, category_for

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\u26AA", "info": "\u26AA"}


def _findings_table(findings: list[dict]) -> list[str]:
    if not findings:
        return ["*No findings.*", ""]
    lines = [
        "| ID | Severity | Project | Resource | Detail |",
        "|----|----------|---------|----------|--------|",
    ]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "info")) if x.get("severity") in SEVERITY_ORDER else 9):
        lines.append(
            f"| {f.get('id', '')} | {f.get('severity', '')} | {f.get('project', '')} | "
            f"{f.get('resource', '')} | {f.get('detail', '')} |"
        )
    lines.append("")
    return lines


def _severity_summary(counts: dict) -> str:
    parts = [f"{counts.get(s, 0)} {s}" for s in SEVERITY_ORDER if counts.get(s, 0)]
    return ", ".join(parts) if parts else "no findings"


def write_markdown_report(output: dict, path: Path, elapsed: float) -> None:
    lines = [
        "# GCP Infrastructure Audit Report",
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
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Findings | {metrics.get('total_findings', 0)} |",
        f"| Risk Chains Identified | {metrics.get('risk_chains_identified', 0)} |",
        f"| Critical | {metrics.get('critical_count', 0)} |",
        f"| High | {metrics.get('high_count', 0)} |",
        "",
        "## Risk Chains",
        "",
    ]

    risk_chains = output.get("risk_chains", [])
    if not risk_chains:
        lines += ["*No cross-domain risk chains identified in this run.*", ""]
    for chain in risk_chains:
        emoji = SEVERITY_EMOJI.get(chain["severity"], "\u26AA")
        lines += [
            f"### {emoji} {chain['chain_id']} — {chain['severity'].upper()}",
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

    all_findings = output.get("findings", [])
    urgent = [f for f in all_findings if f.get("severity") in ("critical", "high")]
    lines += ["## Critical & High Severity Findings", ""]
    lines += _findings_table(urgent)

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
    lines.append("")

    # Full breakdown, grouped by category -> domain, collapsed by default.
    lines += ["## All Findings by Category", ""]
    domain_results = output.get("domain_results", {})
    category_summary = build_category_summary(domain_results)

    for category in CATEGORY_ORDER:
        if category not in category_summary:
            continue
        bucket = category_summary[category]
        domains_in_category = [d for d in bucket["domains"] if d in domain_results]
        category_total = sum(bucket["severity_counts"].values())

        lines += [
            "<details>",
            f"<summary><strong>{category}</strong> — {category_total} finding(s) "
            f"({_severity_summary(bucket['severity_counts'])})</summary>",
            "",
        ]
        for domain in domains_in_category:
            result = domain_results[domain]
            domain_label = DOMAIN_LABELS.get(domain, domain)
            domain_total = sum(result.get("severity_counts", {}).values())
            lines += [
                "<details>",
                f"<summary>{domain_label} — {domain_total} finding(s) "
                f"({_severity_summary(result.get('severity_counts', {}))})</summary>",
                "",
            ]
            lines += _findings_table(result.get("findings", []))
            lines += ["</details>", ""]
        lines += ["</details>", ""]

    # Anything in domain_results whose category wasn't in CATEGORY_ORDER
    # (e.g. a newly-added domain not yet categorised) still gets shown.
    remaining = [d for d in domain_results if category_for(d) not in CATEGORY_ORDER]
    for domain in remaining:
        result = domain_results[domain]
        domain_label = DOMAIN_LABELS.get(domain, domain)
        domain_total = sum(result.get("severity_counts", {}).values())
        lines += [
            "<details>",
            f"<summary>{domain_label} — {domain_total} finding(s) "
            f"({_severity_summary(result.get('severity_counts', {}))})</summary>",
            "",
        ]
        lines += _findings_table(result.get("findings", []))
        lines += ["</details>", ""]

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
