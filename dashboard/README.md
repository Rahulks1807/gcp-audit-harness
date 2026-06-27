# GCP Audit Dashboard

A standalone React dashboard for viewing reports produced by `orchestrator.py` in [gcp-audit-harness](../). Renders the executive summary, severity breakdown, cross-domain risk chains, and the full findings table — built to be handed to a non-technical stakeholder, not just read as raw JSON.

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
| Domain/severity chart | Stacked bar chart of findings per domain, colored by severity |
| Severity donut | Proportional breakdown across critical/high/medium/low/info |
| Risk chains | Expandable cards linking findings that correlate across domains, with blast radius and remediation steps |
| Findings table | Full filterable table by domain and severity |

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

**Add a domain:** update `DOMAIN_LABELS` in `AuditDashboard.jsx` to match any new audit domain added to the harness.

**Change severity colors:** edit `SEVERITY_COLORS` (used in charts) and `SEVERITY_BG` (used in badges).

**Connect to live data:** replace the `useState(SAMPLE_REPORT)` call with a `fetch()` to your reports endpoint, or pass the report in as a prop if embedding this dashboard inside a larger internal tool.
