"""Thin async wrapper around the `gcloud` CLI.

Every domain auditor shells out through `run_gcloud()` instead of depending
on a Python client library per GCP service. Failures (missing binary,
non-existent project, disabled API, insufficient permissions, timeout) are
all treated as "no data available" rather than fatal errors: a warning is
printed and `None` is returned, so one broken check never aborts an entire
domain audit or the overall run.
"""

import asyncio
import json
import shutil
from typing import Any, Optional

_GCLOUD_PATH = shutil.which("gcloud")
_BQ_PATH = shutil.which("bq")

DEFAULT_TIMEOUT_SECONDS = 60


def gcloud_available() -> bool:
    return _GCLOUD_PATH is not None


async def _run_cli(binary_path: Optional[str], binary_name: str, args: list[str], *, timeout: int) -> Optional[Any]:
    if binary_path is None:
        print(f"  [{binary_name}] binary not found on PATH — skipping this check", flush=True)
        return None

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            *args,
            stdin=asyncio.subprocess.DEVNULL,  # never let a disabled-API prompt block waiting for input
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        if proc is not None:
            proc.kill()
        print(f"  [{binary_name}] timed out after {timeout}s: {binary_name} {' '.join(args)}", flush=True)
        return None
    except FileNotFoundError:
        print(f"  [{binary_name}] binary not found on PATH — skipping this check", flush=True)
        return None

    if proc.returncode != 0:
        stderr_text = stderr.decode(errors="replace").strip()
        reason = stderr_text.splitlines()[-1] if stderr_text else f"exit code {proc.returncode}"
        print(f"  [{binary_name}] `{binary_name} {' '.join(args[:3])} ...` failed: {reason}", flush=True)
        return None

    text = stdout.decode(errors="replace").strip()
    if not text:
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print(f"  [{binary_name}] could not parse JSON from `{binary_name} {' '.join(args[:3])} ...`", flush=True)
        return None


async def run_gcloud(args: list[str], *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Optional[Any]:
    """Run `gcloud <args>` and return the parsed JSON output, or None on failure.

    Callers are expected to pass `--format=json...` themselves. An empty but
    successful result (e.g. an empty list) is returned as `[]`, which is
    distinct from `None` (a failed/unavailable check).
    """
    return await _run_cli(_GCLOUD_PATH, "gcloud", args, timeout=timeout)


async def run_bq(args: list[str], *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Optional[Any]:
    """Run `bq <args>` (bundled with the Cloud SDK) and return parsed JSON.

    Callers should pass `--format=prettyjson`/`--format=json` themselves.
    """
    return await _run_cli(_BQ_PATH, "bq", args, timeout=timeout)
