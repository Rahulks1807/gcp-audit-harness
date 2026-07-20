"""Cross-domain risk synthesis — see skills/risk_synthesis.md.

`synthesize()` correlates findings across domains via `cross_domain_tags`
into risk chains, scores effort/impact, and builds a prioritised remediation
plan. If `GEMINI_API_KEY` is set and `google-generativeai` is installed, the
actual reasoning is delegated to Gemini using the risk_synthesis.md prompt
verbatim; otherwise (the default, no-API-key path) a deterministic
rule-based synthesiser implements the same phases so the harness still
produces a complete report with zero external dependencies.
"""

import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Optional

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SKILL_PATH = Path(__file__).resolve().parent.parent / "skills" / "risk_synthesis.md"
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"

REQUIRED_KEYS = ("executive_summary", "risk_chains", "standalone_findings", "remediation_plan", "metrics")


async def synthesize(domain_results: dict) -> dict:
    all_findings = [f for result in domain_results.values() for f in result.get("findings", [])]

    gemini_output = await _try_gemini_synthesis(domain_results)
    if gemini_output is not None:
        return gemini_output

    return _rule_based_synthesis(all_findings)


# ---------------------------------------------------------------------------
# Rule-based fallback — implements risk_synthesis.md phases 1-3 directly.
# ---------------------------------------------------------------------------

def _rule_based_synthesis(all_findings: list[dict]) -> dict:
    chains, chained_ids = _detect_chains(all_findings)

    standalone = sorted(
        (f for f in all_findings if f["id"] not in chained_ids),
        key=lambda f: SEVERITY_RANK.get(f["severity"], len(SEVERITY_RANK)),
    )

    remediation_plan = _build_remediation_plan(chains, standalone)

    total_findings = len(all_findings)
    critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
    high_count = sum(1 for f in all_findings if f["severity"] == "high")

    executive_summary = _build_executive_summary(total_findings, chains, critical_count, high_count)

    return {
        "executive_summary": executive_summary,
        "risk_chains": chains,
        "standalone_findings": standalone,
        "remediation_plan": remediation_plan,
        "metrics": {
            "total_findings": total_findings,
            "risk_chains_identified": len(chains),
            "critical_count": critical_count,
            "high_count": high_count,
        },
    }


def _detect_chains(all_findings: list[dict]) -> tuple[list[dict], set[str]]:
    """Phase 1: group CRITICAL/HIGH findings that share a cross_domain_tag
    across at least two domains into a chain, escalating severity."""
    tag_index: dict[str, list[dict]] = defaultdict(list)
    for f in all_findings:
        for tag in f.get("cross_domain_tags", []) or []:
            tag_index[tag].append(f)

    chains: list[dict] = []
    chained_ids: set[str] = set()
    seen_pairs: set[tuple[str, ...]] = set()
    counter = 1

    for tag, tagged_findings in tag_index.items():
        relevant = [f for f in tagged_findings if f["severity"] in ("critical", "high")]
        domains_involved = {f["domain"] for f in relevant}
        if len(relevant) < 2 or len(domains_involved) < 2:
            continue

        pair_key = tuple(sorted(f["id"] for f in relevant))
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        severities = [f["severity"] for f in relevant]
        # Phase 1, rule 2: two HIGH findings that chain escalate to CRITICAL.
        if "critical" in severities or severities.count("high") >= 2:
            combined_severity = "critical"
        else:
            combined_severity = "high"

        finding_ids = [f["id"] for f in relevant]
        chained_ids.update(finding_ids)
        projects = sorted({f["project"] for f in relevant})

        chains.append({
            "chain_id": f"CHAIN-{counter:03d}",
            "severity": combined_severity,
            "finding_ids": finding_ids,
            "description": (
                f"{' + '.join(finding_ids)} share tag '{tag}': "
                + " ".join(f"[{f['id']}] {f['detail']}" for f in relevant)
            ),
            "blast_radius": f"Resources tagged '{tag}' across {', '.join(projects)}.",
            "remediation_steps": [f"{f['id']}: {f['remediation']}" for f in relevant],
            "effort": _effort_for_chain(relevant),
        })
        counter += 1

    chains.sort(key=lambda c: SEVERITY_RANK.get(c["severity"], len(SEVERITY_RANK)))
    return chains, chained_ids


def _effort_for_chain(findings: list[dict]) -> str:
    # Phase 3 approximation: more findings chained together implies more
    # remediation surface, so effort scales with chain size.
    if len(findings) <= 2:
        return "low"
    if len(findings) <= 4:
        return "medium"
    return "high"


def _build_remediation_plan(chains: list[dict], standalone: list[dict]) -> list[dict]:
    """Phase 3: effort-impact prioritisation — low effort + high impact first."""
    effort_rank = {"low": 0, "medium": 1, "high": 2, "unknown": 1}

    items = [
        {"id": c["chain_id"], "severity": c["severity"], "effort": c["effort"], "impact": "cross-domain risk chain"}
        for c in chains
    ]
    items += [
        {
            "id": f["id"],
            "severity": f["severity"],
            "effort": "low" if f["severity"] in ("low", "info") else "unknown",
            "impact": f["detail"],
        }
        for f in standalone
        if f["severity"] in ("critical", "high", "medium", "low")
    ]

    items.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 9), effort_rank.get(i["effort"], 1)))
    return items


def _build_executive_summary(total_findings: int, chains: list[dict], critical_count: int, high_count: int) -> str:
    domain_word = "findings" if total_findings != 1 else "finding"
    chain_word = "chains" if len(chains) != 1 else "chain"
    top_chain = chains[0] if chains else None

    summary = (
        f"The audit identified {total_findings} {domain_word} "
        f"({critical_count} critical, {high_count} high), including "
        f"{len(chains)} cross-domain risk {chain_word}."
    )
    if top_chain:
        summary += (
            f" The most urgent chain ({top_chain['chain_id']}, {top_chain['severity']}) "
            f"involves {' + '.join(top_chain['finding_ids'])}."
        )
    else:
        summary += " No findings correlated across domains in this run."
    return summary


# ---------------------------------------------------------------------------
# Optional real Gemini synthesis.
# ---------------------------------------------------------------------------

async def _try_gemini_synthesis(domain_results: dict) -> Optional[dict]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    try:
        import google.generativeai as genai
    except ImportError:
        print(
            "  [synthesis] GEMINI_API_KEY is set but google-generativeai isn't installed "
            "(pip install google-generativeai) — falling back to rule-based synthesis",
            flush=True,
        )
        return None

    try:
        genai.configure(api_key=api_key)
        model_name = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        model = genai.GenerativeModel(model_name)

        prompt = (
            SKILL_PATH.read_text()
            + "\n\n## Input Data\n"
            + json.dumps(domain_results, indent=2, default=str)
        )
        response = await asyncio.to_thread(model.generate_content, prompt)
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        result = json.loads(text)
        for key in REQUIRED_KEYS:
            if key not in result:
                raise ValueError(f"Gemini response missing required key '{key}'")
        return result
    except Exception as exc:  # noqa: BLE001 - any failure here should degrade gracefully
        print(f"  [synthesis] Gemini synthesis failed ({exc}) — falling back to rule-based synthesis", flush=True)
        return None
