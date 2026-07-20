"""Main harness entry point.

Runs the six domain auditors in parallel (real asyncio tasks, each shelling
out to the `gcloud` CLI — see `gcp_audit/domains/`), then synthesises their
findings into cross-domain risk chains (`gcp_audit/synthesis.py`), and
writes both a JSON and a Markdown report to `output_dir`.

Earlier versions of this file depended on a fictional `antigravity.sdk`
package; this is a self-contained, runnable replacement with the same CLI
and report shape (so the dashboard in `dashboard/` still works unmodified).
"""

import argparse
import asyncio
import json
import os
import re
import urllib.request
from datetime import datetime
from pathlib import Path

from gcp_audit.categories import CATEGORY_ORDER, DOMAIN_CATEGORIES, DOMAIN_LABELS
from gcp_audit.domains import DOMAIN_MODULES
from gcp_audit.report import write_markdown_report
from gcp_audit.synthesis import synthesize

try:
    from dotenv import load_dotenv

    load_dotenv()  # picks up GEMINI_API_KEY / SLACK_WEBHOOK_URL from a local .env, if present
except ImportError:
    pass

DEFAULT_DOMAINS = list(DOMAIN_MODULES)

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _resolve_env_vars(value):
    """Recursively substitute ${VAR_NAME} placeholders in a config value
    with the matching environment variable (e.g. audit_config.json's
    "slack_webhook": "${SLACK_WEBHOOK_URL}")."""
    if isinstance(value, str):
        return _ENV_VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    return value


async def run_domain_audit(domain: str, projects: list[str], regions: list[str]) -> tuple[str, dict]:
    module = DOMAIN_MODULES[domain]
    print(f"[Subagent: {domain}-auditor] Starting...", flush=True)
    start = datetime.now()
    try:
        result = await module.audit(projects, regions)
    except Exception as exc:  # noqa: BLE001 - one domain failing shouldn't kill the run
        print(f"[Subagent: {domain}-auditor] FAILED: {exc}", flush=True)
        result = {"domain": domain, "projects_audited": projects, "severity_counts": {}, "findings": []}
    elapsed = (datetime.now() - start).total_seconds()
    print(f"[Subagent: {domain}-auditor] Complete ({elapsed:.0f}s) — {len(result['findings'])} findings", flush=True)
    return domain, result


def notify_slack(output: dict, notification: dict) -> None:
    """Best-effort Slack notification, gated on notify_on severities present
    in this run's findings/chains. audit_config.json declares this but the
    original harness never actually sent anything."""
    webhook = notification.get("slack_webhook")
    notify_on = set(notification.get("notify_on", []))
    if not webhook or not notify_on:
        return

    severities_present = {f.get("severity") for f in output.get("findings", [])}
    severities_present |= {c.get("severity") for c in output.get("risk_chains", [])}
    if not severities_present & notify_on:
        return

    metrics = output.get("metrics", {})
    text = (
        f"*GCP audit complete* — {metrics.get('total_findings', 0)} findings, "
        f"{metrics.get('risk_chains_identified', 0)} risk chain(s) "
        f"({metrics.get('critical_count', 0)} critical, {metrics.get('high_count', 0)} high).\n"
        f"{output.get('executive_summary', '')}"
    )
    try:
        request = urllib.request.Request(
            webhook,
            data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(request, timeout=10)
    except Exception as exc:  # noqa: BLE001 - notification failures must not fail the run
        print(f"[notify] Slack notification failed: {exc}", flush=True)


async def run_audit(config_path: str = "audit_config.json") -> dict:
    """Main audit runner."""
    with open(config_path) as f:
        scope = _resolve_env_vars(json.load(f))

    audit_domains = scope.get("audit_domains", DEFAULT_DOMAINS)
    unknown = [d for d in audit_domains if d not in DOMAIN_MODULES]
    if unknown:
        raise ValueError(
            f"Unknown audit domain(s) {unknown} in {config_path}. "
            f"Known domains: {list(DOMAIN_MODULES)}"
        )

    projects = scope["projects"]
    regions = scope.get("regions", ["us-central1"])

    print(f"[{datetime.now().isoformat()}] Starting audit for {len(projects)} projects")
    print(f"Domains: {audit_domains}")
    print(f"Regions: {regions}")
    print("-" * 60)

    start_time = datetime.now()

    domain_results = dict(
        await asyncio.gather(*(run_domain_audit(d, projects, regions) for d in audit_domains))
    )

    print("[Subagent: risk-synthesizer] Starting cross-domain analysis...", flush=True)
    synth_start = datetime.now()
    synthesis_output = await synthesize(domain_results)
    synth_elapsed = (datetime.now() - synth_start).total_seconds()
    print(
        f"[Subagent: risk-synthesizer] Complete ({synth_elapsed:.0f}s) — "
        f"{len(synthesis_output['risk_chains'])} chains identified",
        flush=True,
    )

    elapsed = (datetime.now() - start_time).total_seconds()

    # Dashboard expects a single flat `findings` array across all domains,
    # in addition to the per-domain breakdown under `domain_results`.
    all_findings = [f for result in domain_results.values() for f in result.get("findings", [])]

    output = {
        "executive_summary": synthesis_output["executive_summary"],
        "findings": all_findings,
        "risk_chains": synthesis_output["risk_chains"],
        "standalone_findings": synthesis_output["standalone_findings"],
        "remediation_plan": synthesis_output["remediation_plan"],
        "metrics": synthesis_output["metrics"],
        "domain_results": domain_results,
        # Single source of truth for how the dashboard should group/label
        # domains, so it doesn't need to hardcode 15+ domain names itself.
        "categories": {
            "order": CATEGORY_ORDER,
            "domain_category": {d: DOMAIN_CATEGORIES.get(d, "Other") for d in audit_domains},
            "domain_labels": {d: DOMAIN_LABELS.get(d, d) for d in audit_domains},
        },
    }

    report_dir = Path(scope.get("output_dir", "reports"))
    report_dir.mkdir(exist_ok=True)
    report_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"audit_report_{report_date}.json"

    output["metadata"] = {
        "projects_audited": projects,
        "audit_domains": audit_domains,
        "duration_seconds": round(elapsed, 1),
        "timestamp": datetime.now().isoformat(),
    }

    with open(report_path, "w") as f:
        json.dump(output, f, indent=2)

    md_path = report_dir / f"audit_report_{report_date}.md"
    write_markdown_report(output, md_path, elapsed)

    print(f"\n[{datetime.now().isoformat()}] Audit complete in {elapsed:.1f}s")
    print(f"Report saved: {report_path}")
    print(f"Summary saved: {md_path}")
    print("\n--- Executive Summary ---")
    print(output.get("executive_summary", "No summary generated"))

    notify_slack(output, scope.get("notification", {}))

    return output


def parse_args():
    parser = argparse.ArgumentParser(description="Run the multi-agent GCP infrastructure audit.")
    parser.add_argument(
        "--config",
        default="audit_config.json",
        help="Path to the audit configuration JSON file (default: audit_config.json)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run_audit(config_path=args.config))
