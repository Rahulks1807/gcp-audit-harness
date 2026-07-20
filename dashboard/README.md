# GCP Audit Dashboard

A standalone React dashboard for viewing reports produced by `orchestrator.py` in [gcp-audit-harness](../). Renders the executive summary, severity breakdown, cross-domain risk chains, and findings grouped into collapsible categories — built to be handed to a non-technical stakeholder, not just read as raw JSON.

With 15 audit domains, a flat findings list gets unreadable fast, so findings are grouped into 5 categories (Networking, Identity & Governance, Compute & Containers, Data/Storage/Messaging, Encryption & Secrets), each collapsible and auto-expanded only when it contains a critical/high finding. This grouping comes from the report's own `categories` field (written by `gcp_audit/categories.py`) — the dashboard doesn't need to be updated when new domains are added to the harness.

---

## Quick Start

```bash
npm install
npm run dev
```

Open `http://localhost:5173`. The dashboard loads with sample data so you can see the layout before connecting your own report.

## Loading a Real Report

Click **Load report** in the top right and select the JSON file written by the harness (`reports/audit_report_TIMESTAMP.json`). The dashboard re-renders immediately — no rebuild needed.

To skip the manual upload step, point `SAMPLE_REPORT` in `src/AuditDashboard.jsx` directly at your output, or wire up a `fetch()` call to your `reports/` directory if you're serving this dashboard from the same host as the harness.

## Building for Deployment

```bash
npm run build
```

Outputs static files to `dist/`. Deploy to Cloud Run, Firebase Hosting, or any static host:

```bash
# Example: Firebase Hosting
firebase deploy --only hosting

# Example: Cloud Run (containerized)
gcloud run deploy gcp-audit-dashboard --source .
```

---

## What's Included

| Section | What it shows |
|---------|---------------|
| Metric cards | Projects audited, total findings, risk chain count, audit duration |
| Category/severity chart | Horizontal stacked bar chart of findings per category, colored by severity |
| Severity donut | Proportional breakdown across critical/high/medium/low/info |
| Risk chains | Expandable cards linking findings that correlate across domains, with blast radius and remediation steps |
| Findings by category | Collapsible per-category sections (auto-expanded if they contain a critical/high finding), each with collapsible per-domain sub-sections |
| Findings table | Full table with domain + severity filters, free-text search, and "show more" pagination |

---

## Project Structure

```
audit-dashboard/
├── README.md
├── package.json
├── vite.config.js
├── tailwind.config.js
├── postcss.config.js
├── index.html
└── src/
    ├── main.jsx
    ├── App.jsx
    ├── AuditDashboard.jsx   # Main dashboard component
    └── index.css
```

---

## Customizing

**Add a domain:** nothing to do here — real reports carry their own `categories` block (domain labels + category grouping), generated from `gcp_audit/categories.py`, which the dashboard reads at runtime. Only update `DEFAULT_DOMAIN_LABELS`/`DEFAULT_DOMAIN_CATEGORY`/`DEFAULT_CATEGORY_ORDER` in `AuditDashboard.jsx` if you want the bundled `SAMPLE_REPORT` (or older reports generated before this field existed) to also reflect the new domain.

**Change severity colors:** edit `SEVERITY_COLORS` (used in charts) and `SEVERITY_BG` (used in badges).

**Change which categories auto-expand:** `CategorySection` expands by default when a category has any critical/high finding (`counts.critical > 0 || counts.high > 0`) — adjust that condition in `AuditDashboard.jsx` if you want different default behavior.

**Connect to live data:** replace the `useState(SAMPLE_REPORT)` call with a `fetch()` to your reports endpoint, or pass the report in as a prop if embedding this dashboard inside a larger internal tool.
