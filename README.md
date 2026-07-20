# GCP Audit Harness

A multi-domain GCP infrastructure auditor. Runs **15 domain auditors** in parallel (as real `asyncio` tasks, each shelling out to the `gcloud`/`bq` CLI) across networking, identity, compute, data, and encryption services, then synthesises cross-domain risk chains into a prioritised remediation report — viewable in a companion React dashboard. Both the report and dashboard group the 15 domains into 5 collapsible categories so the output stays readable as coverage grows.

Originally prototyped as a concept against Google Antigravity SDK for the [Agentic Architect Sprint 2026](https://goo.gle/agentic-architect-sprint); this repo now ships a self-contained, runnable implementation (`gcp_audit/`) that only needs Python, the `gcloud` CLI, and the `bq` CLI (both bundled with the Cloud SDK) — no proprietary agent framework required.

---

## What It Does

- **Parallel auditing** — 15 domain auditors run simultaneously as `asyncio` tasks, not sequentially
- **Cross-domain risk correlation** — findings that share a `cross_domain_tags` entry across domains are correlated into risk chains (e.g. a permissive firewall rule + an unguarded service account = critical chain, or a GKE workload identity binding + an exposed Cloud SQL instance = high chain). By default this runs through a deterministic rule-based synthesiser (`gcp_audit/synthesis.py`); set `GEMINI_API_KEY` to delegate the reasoning to Gemini instead (see [Optional: Gemini-powered synthesis](#optional-gemini-powered-synthesis))
- **Structured findings** — every finding follows a shared schema (`schemas/finding.json`) with `cross_domain_tags` enabling correlation
- **Categorized, collapsible reports** — with 15 domains, a flat findings list gets unreadable fast, so both the Markdown report and the dashboard group domains into 5 categories (see below), collapsed by default except for anything critical/high
- **Markdown + JSON reports** — saves both a machine-readable JSON report and a human-readable markdown summary
- **Dashboard** — a standalone React app (in `dashboard/`) that reads the JSON report and renders metrics, charts, collapsible category/domain sections, and expandable risk chain cards
- **Slack notifications** — optionally posts a run summary to a Slack webhook when findings/chains at or above the configured severity are found

### Audit Domains, By Category

Categories (`gcp_audit/categories.py`) are the single source of truth used by both `gcp_audit/report.py` and the dashboard (embedded in each report's `categories` field).

**Networking**

| Domain | What It Checks |
|--------|---------------|
| `networking` | NCC hub/spoke health, BGP session state, CIDR overlaps, stale spokes |
| `firewall` | Permissive ingress rules, missing deny-all defaults, shadow rules |
| `load_balancing` | External backend services with no Cloud Armor policy attached |
| `dns` | Public zones missing DNSSEC, unexpectedly public internal-looking zones |

**Identity & Governance**

| Domain | What It Checks |
|--------|---------------|
| `iam` | Overprivileged bindings, service account key age, PAM entitlement gaps |
| `org_policy` | Missing recommended org policy constraints, log sink/export coverage |

**Compute & Containers**

| Domain | What It Checks |
|--------|---------------|
| `compute` | Public IPs, default service account with full API scope, OS Login, Shielded VM |
| `gke` | Workload identity enablement, Binary Authorization, node auto-upgrade |
| `serverless` | Cloud Run / Cloud Functions unauthenticated (`allUsers`) invocation, ingress settings |
| `artifact_registry` | Public read/write repository access, unvetted remote repositories |

**Data, Storage & Messaging**

| Domain | What It Checks |
|--------|---------------|
| `cloud_sql` | Public IP exposure, authorized networks, backup retention |
| `storage` | Public bucket access, legacy ACLs, uniform bucket-level access |
| `bigquery` | Public dataset access, missing CMEK on PII-labelled datasets |
| `pubsub` | Public topic/subscription IAM bindings, subscriptions with no expiration |

**Encryption & Secrets**

| Domain | What It Checks |
|--------|---------------|
| `kms_secrets` | KMS key rotation + public IAM bindings, Secret Manager public access |

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                     orchestrator.py                       │
│   Loads scope → asyncio.gather() over 15 domain auditors  │
└───────────────────────────┬─────────────────────────────┬─┘
                            │                              │
                            ▼                              ▼
       ┌─────────────────────────────────┐   ... 13 more domain
       │  gcp_audit/domains/*.py         │       auditors, all
       │  Networking · IAM · Firewall ·  │ ← running concurrently
       │  GKE · Cloud SQL · Storage ·    │   as asyncio tasks,
       │  Compute · KMS/Secrets · ...    │   each shelling out to
       └─────────────────────────────────┘   `gcloud`/`bq`
                            │
                            ▼
              ┌────────────────────────────────┐
              │   gcp_audit/synthesis.py       │
              │   Cross-domain risk chain      │
              │   correlation via              │
              │   cross_domain_tags — rule-    │
              │   based by default, or Gemini  │
              │   if GEMINI_API_KEY is set     │
              └────────────────┬───────────────┘
                                ▼
              ┌────────────────────────────────┐
              │   gcp_audit/categories.py      │
              │   Groups the 15 domains into   │
              │   5 categories for the report  │
              │   and dashboard (readability    │
              │   as domain count grows)        │
              └────────────────────────────────┘
```

Each domain auditor in `gcp_audit/domains/` implements the `gcloud`/`bq` calls
and classification rules described in the matching `skills/*.md` file
directly in Python — the `skills/` files remain the human-readable spec for
what each check does and why.

---

## Prerequisites

- Python 3.10+
- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and authenticated — this provides both the `gcloud` and `bq` CLIs that every domain auditor shells out to (`gcloud auth login` and `gcloud auth application-default login`)
- GCP credentials with read access across the audited services. `roles/viewer` on the target projects covers most checks; for full coverage also grant:
  - `roles/iam.securityReviewer`
  - `roles/privilegedaccessmanager.viewer` (IAM domain's PAM entitlement check)
  - `roles/cloudkms.viewer` and `roles/secretmanager.viewer` (KMS & Secret Manager domain)
  - `roles/orgpolicy.policyViewer` and `roles/logging.viewer` (Org Policy & Logging domain)
  - `roles/bigquery.metadataViewer` (BigQuery domain)

  Missing a role just means the affected checks are skipped with a logged warning (see [Expected Output](#expected-output)) — it won't fail the run.
- (Optional) a [Gemini API key](https://ai.google.dev/) if you want real LLM-based risk synthesis instead of the built-in rule-based fallback

---

## Project Structure

```
gcp-audit-harness/
├── README.md
├── requirements.txt
├── audit_config.json          # Audit scope configuration
├── orchestrator.py            # Main harness entry point
├── gcp_audit/                  # Runnable harness implementation
│   ├── gcloud_client.py       # Async `gcloud`/`bq` ... --format=json wrapper
│   ├── models.py              # FindingBuilder — schema-conformant findings
│   ├── categories.py          # Domain -> category grouping (report + dashboard)
│   ├── synthesis.py           # Cross-domain risk chain correlation
│   ├── report.py              # Markdown report rendering (categorized, collapsible)
│   └── domains/                # One auditor module per skill file (15 total)
│       ├── networking.py, firewall.py, load_balancing.py, dns.py
│       ├── iam.py, org_policy.py
│       ├── compute.py, gke.py, serverless.py, artifact_registry.py
│       ├── cloud_sql.py, storage.py, bigquery.py, pubsub.py
│       └── kms_secrets.py
├── schemas/
│   └── finding.json           # Shared finding schema
├── skills/                     # Human-readable spec each domains/ module follows (15 *_audit.md + risk_synthesis.md)
├── dashboard/                 # Standalone React dashboard (see dashboard/README.md)
└── reports/                   # Auto-created, audit outputs written here (gitignored)
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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

A virtual environment is required on most modern setups (e.g. Homebrew's
Python on macOS refuses global `pip install` with an
`externally-managed-environment` error otherwise). Remember to
`source .venv/bin/activate` again in any new terminal before running
`orchestrator.py`.

### 3. Authenticate with GCP

Domain auditors call the `gcloud` CLI directly (not a service-account JSON
key), so it's enough to have an authenticated `gcloud` session:

```bash
gcloud auth login
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
    "networking", "firewall", "load_balancing", "dns",
    "iam", "org_policy",
    "compute", "gke", "serverless", "artifact_registry",
    "cloud_sql", "storage", "bigquery", "pubsub",
    "kms_secrets"
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

A summary is posted to this webhook after each run, but only if at least one
finding or risk chain matches a severity listed in `notification.notify_on`.

### 6. (Optional) Enable Gemini-powered synthesis

By default, cross-domain risk chain detection runs through a deterministic,
dependency-free rule-based synthesiser (`gcp_audit/synthesis.py`) — no API
key required. To delegate that reasoning to Gemini instead:

```bash
pip install google-generativeai   # already in requirements.txt
export GEMINI_API_KEY="your-api-key"
export GEMINI_MODEL="gemini-2.0-flash"   # optional, defaults to gemini-2.0-flash
```

If the Gemini call fails for any reason (bad key, quota, malformed
response), the harness logs a warning and falls back to the rule-based
synthesiser automatically — a run will never fail because of this step.

You can also put either of these in a local `.env` file; it's loaded
automatically via `python-dotenv` if present.

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
[2026-07-20T22:51:44] Starting audit for 2 projects
Domains: ['networking', 'firewall', 'load_balancing', 'dns', 'iam', 'org_policy', 'compute', 'gke', 'serverless', 'artifact_registry', 'cloud_sql', 'storage', 'bigquery', 'pubsub', 'kms_secrets']
Regions: ['asia-south1', 'us-central1']
------------------------------------------------------------
[Subagent: networking-auditor] Starting...
[Subagent: firewall-auditor] Starting...
... (15 subagents start concurrently) ...
[Subagent: kms_secrets-auditor] Complete (7s) — 0 findings
[Subagent: load_balancing-auditor] Complete (8s) — 0 findings
[Subagent: serverless-auditor] Complete (8s) — 0 findings
[Subagent: artifact_registry-auditor] Complete (8s) — 0 findings
[Subagent: networking-auditor] Complete (11s) — 0 findings
[Subagent: iam-auditor] Complete (11s) — 6 findings
[Subagent: org_policy-auditor] Complete (12s) — 10 findings
[Subagent: risk-synthesizer] Starting cross-domain analysis...
[Subagent: risk-synthesizer] Complete (0s) — 0 chains identified

[2026-07-20T22:51:56] Audit complete in 11.7s
Report saved: reports/audit_report_20260720_225156.json
Summary saved: reports/audit_report_20260720_225156.md
```

If a `gcloud` call fails for any reason (API disabled, insufficient
permissions, non-existent project), that individual check is skipped with a
`[gcloud] ...` warning line rather than crashing the run — you'll see this
constantly against the placeholder project names in `audit_config.json`
until you point it at real projects you have access to.

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

| Approach | 15 domains × 3 projects | Finding correlation |
|----------|--------------------------|---------------------|
| Sequential shell scripts | ~45+ minutes | None |
| This harness (parallel `asyncio` auditors) | ~3-5 minutes* | Automatic (rule-based or Gemini) |
| Improvement | **~10× faster** | **Cross-domain chains** |

\* Actual duration depends heavily on how many resources exist per project and API latency — each domain auditor also runs its own per-project checks concurrently via `asyncio.gather`.

---

## Viewing Results: The Dashboard

The `dashboard/` directory contains a standalone React app that reads the JSON report and renders it as metrics, charts, collapsible category/domain sections, and expandable risk chain cards — see `dashboard/README.md` for setup. Quick start:

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173`, click **Load report**, and select your `reports/audit_report_TIMESTAMP.json` file.

---

## Extending the Harness

### Adding a new audit domain

1. Create `skills/your_domain_audit.md` describing the checks, following the same structure as the existing skill files
2. Create `gcp_audit/domains/your_domain.py` implementing an `async def audit(projects, regions) -> dict` that follows the skill file and returns findings matching `schemas/finding.json` (use `gcp_audit.models.FindingBuilder` to build them)
3. Register it in `DOMAIN_MODULES` in `gcp_audit/domains/__init__.py`, and add an ID prefix for it in `_ID_PREFIXES` in `gcp_audit/models.py`
4. Add it to `DOMAIN_CATEGORIES` and `DOMAIN_LABELS` in `gcp_audit/categories.py` (pick an existing category, or add a new one to `CATEGORY_ORDER`) — anything left unmapped falls into an "Other" bucket automatically, but it won't be grouped sensibly
5. Add the `domain` name to the `enum` in `schemas/finding.json` and to `audit_domains` in `audit_config.json`

`orchestrator.py` automatically includes any domain listed in `DOMAIN_MODULES` in the parallel run, passes its findings to `gcp_audit/synthesis.py`, and embeds the category/label mapping in the JSON report's `categories` field so the dashboard picks up new domains without any dashboard code changes.

### Adding new resource types to existing domains

Edit the relevant skill file in `skills/` for documentation, then add the additional `gcloud` calls and classification rules to the matching module in `gcp_audit/domains/`. No changes to `orchestrator.py` are needed.

---

## Limitations

- **Large environments:** For 500+ firewall rules or 100+ projects, shard by project or run domains in separate invocations to keep individual `gcloud` calls fast and avoid rate limits.
- **GKE workload identity binding scope:** `skills/gke_audit.md` calls for inspecting per-KSA IAM bindings inside each cluster, which requires `kubectl` access to the cluster. `gcp_audit/domains/gke.py` doesn't do this (it's `gcloud`-CLI-only) — it tags Workload-Identity-enabled clusters for cross-domain correlation instead, so add cluster-level analysis yourself if you need that check.
- **Rule-based synthesis is mechanical:** the default (no `GEMINI_API_KEY`) chain detection only correlates findings that literally share a `cross_domain_tags` value. It won't catch chains that require broader contextual reasoning the way an LLM-based pass might — treat either path's output as a strong starting point for human review, not a definitive risk score.
- **Credentials:** All domain auditors inherit the same `gcloud`/Application Default Credentials as the orchestrator process. For true isolation, provision per-domain service accounts and run each domain with a different active credential.
- **Read access only:** every `gcloud`/`bq` call made by this harness is a `list`/`get`/`show`/`describe` (no mutations), but it still requires broad read access across 15 services — review the IAM roles above before pointing it at production projects.
- **BigQuery uses the `bq` CLI, not `gcloud`:** dataset-level access control isn't exposed through `gcloud` commands, so `gcp_audit/domains/bigquery.py` shells out to `bq` instead. Make sure the `bq` CLI (bundled with the Cloud SDK) is on `PATH`.
