"""Runnable implementation of the GCP audit harness.

The original prototype imported a fictional `antigravity.sdk` package. This
package replaces that with a small, real asyncio-based harness: domain
auditors shell out to the `gcloud` CLI directly (see `gcp_audit/domains/`),
and `gcp_audit.synthesis` correlates their findings into cross-domain risk
chains, matching the behaviour described in `skills/*.md`.
"""
