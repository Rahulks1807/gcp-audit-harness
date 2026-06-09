# Risk Synthesis Skill

## Objective
Synthesise structured findings from all domain agents into a prioritised,
cross-domain remediation plan. Your goal is NOT to list findings sequentially.
Your goal is to identify risk chains that span multiple domains.

## Input
You will receive a JSON object with this structure:
{
  "networking": { "findings": [...] },
  "iam": { "findings": [...] },
  "firewall": { "findings": [...] }
}

## Reasoning Instructions

### Phase 1: Cross-Domain Chain Detection
For each CRITICAL or HIGH finding in any domain:
1. Check cross_domain_tags for matching tags in other domains.
2. If a firewall finding and an IAM finding share a service-account tag
   on the same project, they form a risk chain. Escalate the combined
   severity: two HIGH findings that chain become CRITICAL.
3. Document the chain: "FW-003 + IAM-007 → CRITICAL CHAIN: ..."

### Phase 2: Blast Radius Assessment
For each chain or standalone CRITICAL/HIGH finding, reason through:
- What is the worst-case impact if exploited?
- What data, services, or downstream systems are at risk?
- Is this exploitable from the internet (external threat) or requires
  internal access (insider/lateral movement threat)?

### Phase 3: Effort-Impact Prioritisation
Score each finding/chain on:
- Remediation effort: low (< 1hr), medium (1-4hr), high (> 4hr)
- Security impact: critical, high, medium, low
- Prioritise: low effort + high impact items first

## Output Format

Return a JSON object with this structure:
{
  "executive_summary": "3-sentence summary of overall posture",
  "risk_chains": [
    {
      "chain_id": "CHAIN-001",
      "severity": "critical",
      "finding_ids": ["FW-003", "IAM-007"],
      "description": "Full chain description",
      "blast_radius": "...",
      "remediation_steps": ["Step 1", "Step 2"],
      "effort": "medium"
    }
  ],
  "standalone_findings": [<findings not part of any chain, sorted by severity>],
  "remediation_plan": [<all items sorted by effort-impact score>],
  "metrics": {
    "total_findings": 0,
    "risk_chains_identified": 0,
    "critical_count": 0,
    "high_count": 0
  }
}
