import React, { useState, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell } from 'recharts';
import { ChevronDown, ChevronUp, AlertTriangle, Link2, Clock, FolderTree, Upload } from 'lucide-react';

// ---------------------------------------------------------------------------
// Sample audit report shape. Replace this with the JSON produced by
// orchestrator.py (reports/audit_report_TIMESTAMP.json) — either paste it in
// via the "Load report" button, or wire this component up to fetch the file
// directly from your reports/ directory.
// ---------------------------------------------------------------------------
const SAMPLE_REPORT = {
  metadata: {
    projects_audited: ["prod-network-hub", "prod-app-tier-1", "prod-data-tier"],
    audit_domains: ["networking", "iam", "firewall", "gke", "cloud_sql", "storage"],
    duration_seconds: 167,
    timestamp: "2026-06-09T02:01:40Z"
  },
  executive_summary:
    "The audit identified 19 findings across six domains, including three cross-domain risk chains. The most urgent chain combines an internet-facing firewall rule with an unguarded owner-level service account in prod-app-tier-1. Seven findings can be resolved within a single sprint with low engineering effort.",
  findings: [
    { id: "FW-003", domain: "firewall", severity: "high", project: "prod-app-tier-1", resource: "allow-app-ingress", detail: "Ingress rule permits 0.0.0.0/0 on port 8080.", remediation: "Restrict source ranges to known CIDRs." },
    { id: "IAM-007", domain: "iam", severity: "high", project: "prod-app-tier-1", resource: "app-sa@prod-app-tier-1.iam.gserviceaccount.com", detail: "roles/editor binding with no PAM entitlement coverage.", remediation: "Wrap binding in a PAM entitlement, 1hr max duration." },
    { id: "GKE-002", domain: "gke", severity: "critical", project: "prod-app-tier-1", resource: "cluster-prod-app/workload-identity", detail: "Pod service account has direct IAM binding to Cloud SQL client role.", remediation: "Scope workload identity to namespace-level binding only." },
    { id: "SQL-001", domain: "cloud_sql", severity: "high", project: "prod-data-tier", resource: "customer-records-db", detail: "Public IP enabled with authorized network 0.0.0.0/0.", remediation: "Disable public IP, switch to private services access." },
    { id: "GCS-002", domain: "storage", severity: "medium", project: "prod-app-tier-1", resource: "build-artifacts-bucket", detail: "Bucket IAM policy grants allUsers objectViewer.", remediation: "Remove allUsers binding, use signed URLs instead." },
    { id: "IAM-003", domain: "iam", severity: "medium", project: "prod-app-tier-1", resource: "ci-deploy-sa", detail: "User-managed key is 142 days old.", remediation: "Rotate key, migrate to Workload Identity Federation." },
    { id: "NET-001", domain: "networking", severity: "high", project: "prod-network-hub", resource: "spoke-asia-south1", detail: "BGP session down on active production spoke.", remediation: "Investigate Cloud Router peering, check on-prem router config." },
    { id: "NET-002", domain: "networking", severity: "medium", project: "prod-network-hub", resource: "spoke-us-central1-b", detail: "CIDR range overlaps with spoke-us-central1-a (10.4.0.0/16).", remediation: "Re-allocate non-overlapping CIDR block." },
    { id: "GKE-001", domain: "gke", severity: "medium", project: "prod-app-tier-1", resource: "cluster-prod-app", detail: "Binary Authorization is not enabled.", remediation: "Enable Binary Authorization with a default attestor policy." },
    { id: "SQL-002", domain: "cloud_sql", severity: "medium", project: "prod-data-tier", resource: "analytics-db", detail: "Automated backups retention is 1 day (below 7-day baseline).", remediation: "Increase backup retention to 7 days minimum." },
    { id: "FW-001", domain: "firewall", severity: "medium", project: "prod-network-hub", resource: "default-allow-internal", detail: "No explicit deny-all ingress rule below priority 65534.", remediation: "Add explicit deny-all rule at lowest priority." },
    { id: "FW-002", domain: "firewall", severity: "critical", project: "prod-data-tier", resource: "legacy-ssh-access", detail: "0.0.0.0/0 permitted on port 22.", remediation: "Restrict to bastion host IP or use IAP tunneling." },
    { id: "GCS-001", domain: "storage", severity: "critical", project: "prod-data-tier", resource: "customer-exports-bucket", detail: "Bucket has uniform bucket-level access disabled with legacy ACLs granting allAuthenticatedUsers read.", remediation: "Enable uniform bucket-level access, audit and remove legacy ACLs." },
    { id: "IAM-001", domain: "iam", severity: "high", project: "prod-data-tier", resource: "data-pipeline-sa", detail: "roles/owner bound at project level.", remediation: "Downscope to specific roles needed by the pipeline." },
    { id: "IAM-002", domain: "iam", severity: "low", project: "prod-network-hub", resource: "network-admin-group", detail: "Group has 14 members, 3 inactive in last 90 days.", remediation: "Review group membership, remove inactive users." },
    { id: "NET-003", domain: "networking", severity: "info", project: "prod-app-tier-1", resource: "spoke-test-temp", detail: "No traffic in last 30 days.", remediation: "Confirm spoke is still needed, decommission if not." },
    { id: "GKE-003", domain: "gke", severity: "low", project: "prod-data-tier", resource: "cluster-data-pipeline", detail: "Node auto-upgrade is disabled.", remediation: "Enable node auto-upgrade for security patch cadence." },
    { id: "SQL-003", domain: "cloud_sql", severity: "info", project: "prod-data-tier", resource: "staging-db", detail: "Instance has not been queried in 21 days.", remediation: "Confirm staging-db is still required." },
    { id: "FW-004", domain: "firewall", severity: "low", project: "prod-app-tier-1", resource: "legacy-rdp-rule", detail: "Disabled rule still present in ruleset (shadow rule).", remediation: "Delete unused disabled rule for clarity." }
  ],
  risk_chains: [
    {
      chain_id: "CHAIN-001",
      severity: "critical",
      finding_ids: ["FW-003", "IAM-007"],
      description: "Internet-facing firewall rule (FW-003) combined with an unguarded owner-level service account (IAM-007) in prod-app-tier-1. A compromised workload reachable on port 8080 could exfiltrate all project resources without triggering PAM justification alerts.",
      blast_radius: "All resources in prod-app-tier-1, including 3 PII-tagged Cloud Storage buckets and the CI/CD deploy pipeline.",
      remediation_steps: [
        "Restrict FW-003 source ranges to known internal CIDRs. Effort: 30 minutes.",
        "Wrap the IAM-007 role binding in a PAM entitlement with 1-hour max duration. Effort: 2 hours."
      ],
      effort: "low"
    },
    {
      chain_id: "CHAIN-002",
      severity: "high",
      finding_ids: ["GKE-002", "SQL-001"],
      description: "GKE workload identity binding (GKE-002) grants a pod direct access to a Cloud SQL instance with public IP enabled (SQL-001). Any compromised pod in the cluster can reach the customer-records-db directly from the internet path.",
      blast_radius: "Customer records database reachable from any compromised pod in cluster-prod-app, bypassing the intended private network boundary.",
      remediation_steps: [
        "Disable public IP on customer-records-db, switch to private services access. Effort: 1 hour.",
        "Scope the GKE workload identity binding to namespace level rather than cluster-wide. Effort: 1.5 hours."
      ],
      effort: "medium"
    },
    {
      chain_id: "CHAIN-003",
      severity: "medium",
      finding_ids: ["GCS-002", "IAM-003"],
      description: "A publicly readable storage bucket (GCS-002) combined with a stale service account key (IAM-003) that still holds write access to the same bucket increases the risk of build artifact tampering.",
      blast_radius: "Build artifacts served from build-artifacts-bucket could be tampered with if the stale key is compromised.",
      remediation_steps: [
        "Remove the allUsers binding on build-artifacts-bucket. Effort: 15 minutes.",
        "Rotate the 142-day-old service account key. Effort: 30 minutes."
      ],
      effort: "low"
    }
  ]
};

const DOMAIN_LABELS = {
  networking: "Networking",
  iam: "IAM",
  firewall: "Firewall",
  gke: "GKE",
  cloud_sql: "Cloud SQL",
  storage: "Storage"
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS = {
  critical: "#A32D2D",
  high: "#BA7517",
  medium: "#185FA5",
  low: "#5F5E5A",
  info: "#888780"
};

const SEVERITY_BG = {
  critical: "bg-red-50 text-red-800 border-red-200",
  high: "bg-amber-50 text-amber-800 border-amber-200",
  medium: "bg-blue-50 text-blue-800 border-blue-200",
  low: "bg-gray-50 text-gray-700 border-gray-200",
  info: "bg-gray-50 text-gray-600 border-gray-200"
};

function SeverityBadge({ severity }) {
  return (
    <span className={`inline-flex items-center text-xs font-medium px-2 py-0.5 rounded-md border ${SEVERITY_BG[severity] || SEVERITY_BG.info}`}>
      {severity}
    </span>
  );
}

function MetricCard({ label, value, icon: Icon }) {
  return (
    <div className="bg-gray-50 rounded-lg p-4 flex items-center justify-between">
      <div>
        <p className="text-xs text-gray-500 mb-1">{label}</p>
        <p className="text-2xl font-medium text-gray-900">{value}</p>
      </div>
      {Icon && <Icon className="w-5 h-5 text-gray-400" />}
    </div>
  );
}

function DomainSeverityChart({ findings }) {
  const data = useMemo(() => {
    const domains = Object.keys(DOMAIN_LABELS);
    return domains.map((domain) => {
      const row = { domain: DOMAIN_LABELS[domain] };
      SEVERITY_ORDER.forEach((sev) => {
        row[sev] = findings.filter((f) => f.domain === domain && f.severity === sev).length;
      });
      return row;
    });
  }, [findings]);

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <XAxis dataKey="domain" tick={{ fontSize: 12, fill: "#5F5E5A" }} axisLine={{ stroke: "#E5E3DA" }} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "#5F5E5A" }} axisLine={false} tickLine={false} />
        <Tooltip />
        {SEVERITY_ORDER.map((sev) => (
          <Bar key={sev} dataKey={sev} stackId="a" fill={SEVERITY_COLORS[sev]} name={sev} radius={[2, 2, 0, 0]} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

function SeverityDonut({ findings }) {
  const data = useMemo(
    () =>
      SEVERITY_ORDER.map((sev) => ({
        name: sev,
        value: findings.filter((f) => f.severity === sev).length
      })).filter((d) => d.value > 0),
    [findings]
  );

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip />
        <Legend
          verticalAlign="bottom"
          height={36}
          formatter={(value) => <span className="text-xs text-gray-600 capitalize">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

function RiskChainCard({ chain, findingsById }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-50 transition"
      >
        <SeverityBadge severity={chain.severity} />
        <span className="text-sm font-medium text-gray-900">{chain.chain_id}</span>
        <span className="text-sm text-gray-500 flex items-center gap-1">
          <Link2 className="w-3.5 h-3.5" />
          {chain.finding_ids.join(" + ")}
        </span>
        <span className="ml-auto text-gray-400">
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </span>
      </button>

      <div className="px-4 pb-3">
        <p className="text-sm text-gray-600">{chain.description}</p>
      </div>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-100 bg-gray-50/50 space-y-3">
          <div>
            <p className="text-xs font-medium text-gray-500 mb-1">Linked findings</p>
            <div className="flex flex-wrap gap-2">
              {chain.finding_ids.map((id) => {
                const f = findingsById[id];
                if (!f) return null;
                return (
                  <div key={id} className="text-xs bg-white border border-gray-200 rounded-md px-2 py-1">
                    <span className="font-mono text-gray-700">{id}</span>
                    <span className="text-gray-500"> — {f.resource}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div>
            <p className="text-xs font-medium text-gray-500 mb-1">Blast radius</p>
            <p className="text-sm text-gray-700">{chain.blast_radius}</p>
          </div>
          <div>
            <p className="text-xs font-medium text-gray-500 mb-1">Remediation steps</p>
            <ul className="text-sm text-gray-700 space-y-1 list-disc list-inside">
              {chain.remediation_steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

function FindingsTable({ findings }) {
  const [domainFilter, setDomainFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  const filtered = findings
    .filter((f) => domainFilter === "all" || f.domain === domainFilter)
    .filter((f) => severityFilter === "all" || f.severity === severityFilter)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-3">
        <select
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          className="text-sm border border-gray-200 rounded-md px-2 py-1.5 bg-white"
        >
          <option value="all">All domains</option>
          {Object.entries(DOMAIN_LABELS).map(([key, label]) => (
            <option key={key} value={key}>{label}</option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="text-sm border border-gray-200 rounded-md px-2 py-1.5 bg-white"
        >
          <option value="all">All severities</option>
          {SEVERITY_ORDER.map((sev) => (
            <option key={sev} value={sev}>{sev}</option>
          ))}
        </select>
        <span className="text-sm text-gray-400 self-center ml-1">{filtered.length} findings</span>
      </div>

      <div className="overflow-x-auto border border-gray-200 rounded-lg">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 text-left text-gray-500 text-xs">
              <th className="px-3 py-2 font-medium">ID</th>
              <th className="px-3 py-2 font-medium">Domain</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Resource</th>
              <th className="px-3 py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id} className="border-t border-gray-100">
                <td className="px-3 py-2 font-mono text-xs text-gray-700 whitespace-nowrap">{f.id}</td>
                <td className="px-3 py-2 text-gray-700 whitespace-nowrap">{DOMAIN_LABELS[f.domain]}</td>
                <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                <td className="px-3 py-2 font-mono text-xs text-gray-600 whitespace-nowrap max-w-[160px] truncate" title={f.resource}>{f.resource}</td>
                <td className="px-3 py-2 text-gray-600">{f.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function AuditDashboard() {
  const [report, setReport] = useState(SAMPLE_REPORT);
  const [fileError, setFileError] = useState("");

  const findingsById = useMemo(
    () => Object.fromEntries(report.findings.map((f) => [f.id, f])),
    [report]
  );

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    report.findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    return counts;
  }, [report]);

  function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const parsed = JSON.parse(evt.target.result);
        if (!parsed.findings) throw new Error("Missing findings array");
        setReport(parsed);
        setFileError("");
      } catch (err) {
        setFileError("Could not parse this file. Expecting the JSON report produced by orchestrator.py.");
      }
    };
    reader.readAsText(file);
  }

  return (
    <div className="max-w-5xl mx-auto p-6 bg-white">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-xl font-medium text-gray-900">GCP infrastructure audit</h1>
          <p className="text-sm text-gray-500 mt-1">
            {report.metadata.projects_audited.join(", ")}
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm border border-gray-200 rounded-md px-3 py-2 cursor-pointer hover:bg-gray-50 transition">
          <Upload className="w-4 h-4 text-gray-500" />
          Load report
          <input type="file" accept="application/json" className="hidden" onChange={handleFileUpload} />
        </label>
      </div>

      {fileError && (
        <div className="mb-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2">
          {fileError}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <MetricCard label="Projects audited" value={report.metadata.projects_audited.length} icon={FolderTree} />
        <MetricCard label="Total findings" value={report.findings.length} icon={AlertTriangle} />
        <MetricCard label="Risk chains" value={report.risk_chains.length} icon={Link2} />
        <MetricCard label="Audit duration" value={`${Math.floor(report.metadata.duration_seconds / 60)}m ${report.metadata.duration_seconds % 60}s`} icon={Clock} />
      </div>

      <div className="mb-6 bg-gray-50 rounded-lg p-4">
        <p className="text-xs font-medium text-gray-500 mb-1.5">Executive summary</p>
        <p className="text-sm text-gray-700 leading-relaxed">{report.executive_summary}</p>
      </div>

      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div>
          <p className="text-sm font-medium text-gray-700 mb-2">Findings by domain and severity</p>
          <DomainSeverityChart findings={report.findings} />
        </div>
        <div>
          <p className="text-sm font-medium text-gray-700 mb-2">Severity breakdown</p>
          <SeverityDonut findings={report.findings} />
        </div>
      </div>

      <div className="mb-8">
        <p className="text-sm font-medium text-gray-700 mb-3">Cross-domain risk chains</p>
        <div className="space-y-2">
          {report.risk_chains.map((chain) => (
            <RiskChainCard key={chain.chain_id} chain={chain} findingsById={findingsById} />
          ))}
        </div>
      </div>

      <div>
        <p className="text-sm font-medium text-gray-700 mb-3">All findings</p>
        <FindingsTable findings={report.findings} />
      </div>
    </div>
  );
}
