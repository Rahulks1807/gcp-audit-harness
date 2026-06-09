# gcp-audit-harness
A practical guide to parallel subagent orchestration, Gemini 3.5 reasoning, and cross-domain risk correlation for cloud architects

##############
# GCP Audit Harness

A multi-agent GCP infrastructure auditor built with Google Antigravity SDK. Spawns parallel domain subagents to simultaneously audit networking, IAM, and firewall posture across multiple GCP projects, then uses Gemini 3.5 reasoning to synthesise cross-domain risk chains into a prioritised remediation report.

Built as part of the [Agentic Architect Sprint 2026](https://goo.gle/agentic-architect-sprint) using Google Antigravity 2.0 and Antigravity SDK.

---

## What It Does

- **Parallel auditing** — three domain agents (networking, IAM, firewall) run simultaneously, not sequentially
- **Cross-domain risk correlation** — Gemini 3.5 identifies risk chains that span domains (e.g. a permissive firewall rule + an unguarded service account = critical chain)
- **Structured findings** — every finding follows a shared schema with `cross_domain_tags` enabling correlation
- **Markdown + JSON reports** — saves both a machine-readable JSON report and a human-readable markdown summary

### Audit Domains

| Domain | What It Checks |
|--------|---------------|
| Networking | NCC hub/spoke health, BGP session state, CIDR overlaps, stale spokes |
| IAM | Overprivileged bindings, service account key age, PAM entitlement gaps |
| Firewall | Permissive ingress rules, missing deny-all defaults, shadow rules |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              ORCHESTRATOR AGENT                     │
│  Receives scope → builds task graph → manages store │
└────────┬────────────┬────────────┬──────────────────┘
         │            │            │
         ▼            ▼            ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │Networking│  │   IAM    │  │ Firewall │  ← Parallel Subagents
  │  Agent   │  │  Agent   │  │  Agent   │
  └──────────┘  └──────────┘  └──────────┘
         │            │            │
         └────────────┴────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │  GEMINI 3.5 SYNTHESIS  │
         │  Cross-domain risk     │
         │  correlation + report  │
         └────────────────────────┘
```

---

## Prerequisites

- Google Antigravity 2.0 installed and authenticated
- Python 3.10+
- GCP credentials with the following roles on target projects:
  - `roles/viewer`
  - `roles/iam.securityReviewer`
  - `roles/privilegedaccessmanager.viewer`
- `gcloud` CLI authenticated with Application Default Credentials

---

## Project Structure

```
gcp-audit-harness/
├── README.md
├── requirements.txt
├── audit_config.json          # Audit scope configuration
├── orchestrator.py            # Main harness entry point
├── schemas/
│   └── finding.json           # Shared finding schema
├── skills/
│   ├── networking_audit.md    # NCC, VPC, BGP audit skill
│   ├── iam_audit.md           # IAM, PAM, service account audit skill
│   ├── firewall_audit.md      # Firewall rules audit skill
│   └── risk_synthesis.md      # Cross-domain Gemini 3.5 synthesis skill
└── reports/                   # Auto-created, audit outputs written here
```

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/your-handle/gcp-audit-harness.git
cd gcp-audit-harness
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Authenticate with GCP

```bash
gcloud auth application-default login
```

### 4. Configure your audit scope

Edit `audit_config.json` to set your target projects, regions, and audit domains:

```json
{
  "projects": [
    "your-project-1",
    "your-project-2"
  ],
  "regions": [
    "us-central1",
    "asia-south1"
  ],
  "audit_domains": [
    "networking",
    "iam",
    "firewall"
  ],
  "output_dir": "reports",
  "notification": {
    "slack_webhook": "${SLACK_WEBHOOK_URL}",
    "notify_on": ["critical", "high"]
  }
}
```

### 5. (Optional) Set Slack notifications

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

---

## Running the Audit

```bash
python orchestrator.py
```

To point at a custom config file:

```bash
python orchestrator.py --config my_custom_config.json
```

### Expected Output

```
[2026-06-09T02:00:01] Starting audit for 3 projects
Domains: ['networking', 'iam', 'firewall']
Regions: ['asia-south1', 'us-central1']
------------------------------------------------------------
[Subagent: networking-auditor] Starting...
[Subagent: iam-auditor] Starting...
[Subagent: firewall-auditor] Starting...
[Subagent: networking-auditor] Complete (47s) — 3 findings
[Subagent: iam-auditor] Complete (51s) — 5 findings
[Subagent: firewall-auditor] Complete (38s) — 4 findings
[Subagent: risk-synthesizer] Starting cross-domain analysis...
[Subagent: risk-synthesizer] Complete (23s) — 2 chains identified

[2026-06-09T02:01:40] Audit complete in 99.2s
Report saved: reports/audit_report_20260609_020140.json
Summary saved: reports/audit_report_20260609_020140.md
```

---

## Understanding the Output

Reports are saved to the `reports/` directory in two formats:

**JSON (`audit_report_TIMESTAMP.json`)** — full machine-readable output including all raw findings, risk chains, and the remediation plan. Use this for downstream tooling or dashboards.

**Markdown (`audit_report_TIMESTAMP.md`)** — human-readable summary with an executive summary, metrics table, risk chain details, and prioritised remediation plan. Paste directly into a wiki or incident ticket.

### Cross-Domain Risk Chain Example

```json
{
  "chain_id": "CHAIN-001",
  "severity": "critical",
  "finding_ids": ["FW-003", "IAM-007"],
  "description": "Firewall rule allows 0.0.0.0/0 on port 8080 (FW-003) combined with an unguarded roles/editor binding on the same project (IAM-007). A compromised workload reachable from the internet could exfiltrate all project resources without triggering PAM justification alerts.",
  "blast_radius": "All resources in prod-app-tier-1 including PII-tagged Cloud Storage buckets.",
  "remediation_steps": [
    "Restrict firewall source ranges to known CIDRs. Effort: 30 minutes.",
    "Wrap roles/editor in a PAM entitlement with 1-hour max duration. Effort: 2 hours."
  ],
  "effort": "medium"
}
```

---

## Performance

| Approach | 3 domains × 3 projects | Finding correlation |
|----------|------------------------|---------------------|
| Sequential shell scripts | ~18 minutes | None |
| This harness (parallel subagents) | ~99 seconds | Automatic (Gemini 3.5) |
| Improvement | **10.9× faster** | **Cross-domain chains** |

---

## Extending the Harness

### Adding a new audit domain

1. Create `skills/your_domain_audit.md` following the same structure as the existing skill files
2. Ensure your skill returns findings matching `schemas/finding.json`
3. Add your domain name to `audit_domains` in `audit_config.json`

The orchestrator will automatically include it in the parallel task graph and pass its findings to the synthesis layer.

### Adding new resource types to existing domains

Edit the relevant skill file in `skills/` and add the additional `gcloud` commands and classification rules. No changes to `orchestrator.py` are needed.

---

## Limitations

- **Large environments:** For 500+ firewall rules or 100+ projects, shard by project before spawning domain agents to avoid context window saturation.
- **Gemini 3.5 reasoning:** Occasionally over-prioritises findings that resemble known attack patterns. Treat output as a starting point for human review, not a definitive risk score.
- **Token costs:** The synthesis step scales with total finding count. Use `TokenBudgetMonitor` with `on_exceed="kill"` in production for cost predictability.
- **Credentials:** All subagents inherit the same Application Default Credentials as the orchestrator. For true isolation, provision per-domain service accounts.

---

## Related Blog Post

Full walkthrough and architecture explanation: [Building a Multi-Agent GCP Infrastructure Auditor with Google Antigravity SDK](https://medium.com/@your-handle/blog-link)

---

## Hashtags

`#GoogleAntigravity` `#AgenticArchitect` `#GoogleCloud` `#GCP` `#CloudSecurity` `#MultiAgent`
