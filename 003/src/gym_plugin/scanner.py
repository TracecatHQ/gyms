"""Pinned Nuclei version-suspicion scan for Gym 003."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .probe import (
    INGRESS,
    SCENARIO,
    VIRTUAL_HOST,
    FixedHTTPSession,
    ProbeError,
    _safe_response_fingerprint,
    _validated_context,
    _write_json,
)


TEMPLATE_REVISION = "b78b60c84a754c0ce2a8b9f0710edc8987adeb85"
TEMPLATE_ID = "CVE-2026-21858"
TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "assets" / "nuclei" / "CVE-2026-21858.yaml"
NUCLEI_BINARY = "nuclei"


def _parse_jsonl(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        template_id = item.get("template-id") or item.get("templateID") or item.get("template")
        if template_id != TEMPLATE_ID:
            continue
        findings.append(
            {
                "template_id": TEMPLATE_ID,
                "cve": TEMPLATE_ID,
                "severity": "critical",
                "matched_at": item.get("matched-at") or item.get("matched"),
                "extracted_results": item.get("extracted-results", []),
                "classification": "version_suspicion",
            }
        )
    return findings


def _preflight(timeout: float) -> dict[str, Any]:
    session = FixedHTTPSession(timeout=timeout)
    status, _, body = session.request("GET", "/signin")
    return {"status": status, **_safe_response_fingerprint(body)}


def run_scan(context: dict[str, Any]) -> dict[str, Any]:
    """Run one immutable template against the one server-resolved ingress.

    The result deliberately says "suspected".  This template fingerprints an
    affected version; it does not replace the independent active verifier.
    """

    evidence_dir, timeout = _validated_context(context)
    if not TEMPLATE_PATH.is_file():
        raise ProbeError(f"pinned Nuclei template missing: {TEMPLATE_PATH}")
    nuclei = shutil.which(NUCLEI_BINARY)
    if nuclei is None:
        return {
            "verdict": "inconclusive",
            "finding": None,
            "evidence": [],
            "error": "pinned scanner executable is unavailable",
        }

    try:
        preflight = _preflight(timeout)
    except (OSError, TimeoutError) as exc:
        return {
            "verdict": "inconclusive",
            "finding": None,
            "evidence": [],
            "error": f"target preflight failed: {type(exc).__name__}",
        }
    if preflight["status"] >= 500:
        return {
            "verdict": "inconclusive",
            "finding": None,
            "evidence": [],
            "error": f"target preflight returned HTTP {preflight['status']}",
        }

    command = [
        nuclei,
        "-target",
        INGRESS,
        "-header",
        f"Host: {VIRTUAL_HOST}",
        "-t",
        str(TEMPLATE_PATH),
        "-jsonl",
        "-silent",
        "-no-interactsh",
        "-timeout",
        str(max(1, min(int(timeout), 30))),
        "-retries",
        "1",
        "-disable-update-check",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=min(timeout + 10, 70),
        )
    except subprocess.TimeoutExpired:
        return {
            "verdict": "inconclusive",
            "finding": None,
            "evidence": [],
            "error": "scanner timed out",
        }

    findings = _parse_jsonl(completed.stdout)
    if completed.returncode != 0:
        verdict = "inconclusive"
        error = "scanner failed without a trustworthy result"
    elif findings:
        verdict = "suspected_vulnerable_version"
        error = None
    else:
        verdict = "not_detected"
        error = None

    evidence = {
        "scenario": SCENARIO,
        "scanner": "nuclei",
        "template_id": TEMPLATE_ID,
        "template_revision": TEMPLATE_REVISION,
        "classification": "version_suspicion",
        "preflight": preflight,
        "exit_code": completed.returncode,
        "verdict": verdict,
        "findings": findings,
        "stderr_present": bool(completed.stderr.strip()),
    }
    path = evidence_dir / SCENARIO / "scan" / f"{uuid.uuid4().hex}.json"
    _write_json(path, evidence)
    return {
        "verdict": verdict,
        "finding": findings[0] if findings else None,
        "evidence": [str(path)],
        "error": error,
    }
