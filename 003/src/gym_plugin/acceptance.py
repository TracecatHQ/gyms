"""Active and deterministic acceptance checks for Gym 003."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Callable

from .probe import SCENARIO, verify, _validated_context, _write_json
from .scanner import run_scan
from .traffic import run_benign_suite


RULE_ID = "gym003-supplier-upload-content-type"
RULE_IDS = {"LOG_ONLY": 9300301, "BLOCK": 9300302}
ACCEPTANCE_POLICY = {
    "scenario": SCENARIO,
    "revision": 1,
    "route": "/form/supplier-intake",
    "method": "POST",
    "allowed_content_type": "multipart/form-data",
}


def _event_matches(events: Any, mode: str) -> bool:
    if not isinstance(events, list):
        return False
    for event in events:
        if not isinstance(event, dict):
            continue
        event_rule_id = event.get("rule_id")
        if str(event_rule_id) == str(RULE_IDS[mode]) or RULE_ID in str(event.get("message", "")):
            return True
    return False


def _benign_statuses(result: Any) -> dict[str, list[int | None]]:
    output: dict[str, list[int | None]] = {}
    if not isinstance(result, dict):
        return output
    for item in result.get("transactions", []):
        if not isinstance(item, dict):
            continue
        output.setdefault(str(item.get("name")), []).append(item.get("status"))
    return output


def _safe_terminal(result: Any) -> bool:
    """A failed, timed-out, or malformed job must never count as success."""

    if not isinstance(result, dict):
        return False
    if result.get("status") in {"failed", "timed_out", "running", "queued"}:
        return False
    if result.get("error"):
        return False
    return result.get("verdict") not in {None, "inconclusive"}


def assess_acceptance(report: dict[str, Any]) -> dict[str, Any]:
    """Assess captured phases without performing network or firewall changes."""

    baseline = report.get("baseline", {})
    log_only = report.get("log_only", {})
    block = report.get("block", {})
    removal = report.get("removal", {})
    guards = report.get("failure_guards", {})

    baseline_benign = _benign_statuses(baseline.get("benign"))
    checks = {
        "baseline_scanner_suspects_version": baseline.get("scan", {}).get("verdict")
        == "suspected_vulnerable_version",
        "baseline_rce_confirmed": baseline.get("verify", {}).get("verdict") == "confirmed_rce",
        "baseline_benign_passes": baseline.get("benign", {}).get("passed") is True,
        "log_attack_still_succeeds": log_only.get("verify", {}).get("verdict") == "confirmed_rce",
        "log_event_correlated": _event_matches(log_only.get("waf_events"), "LOG_ONLY"),
        "log_benign_unchanged": log_only.get("benign", {}).get("passed") is True
        and _benign_statuses(log_only.get("benign")) == baseline_benign,
        "block_stops_fresh_attack": block.get("verify", {}).get("verdict") == "blocked_by_waf",
        "block_event_correlated": _event_matches(block.get("waf_events"), "BLOCK"),
        "block_benign_unchanged": block.get("benign", {}).get("passed") is True
        and _benign_statuses(block.get("benign")) == baseline_benign,
        "removal_restores_rce": removal.get("verify", {}).get("verdict") == "confirmed_rce",
        "outage_not_success": guards.get("outage_not_success") is True,
        "malformed_proposal_rejected": guards.get("malformed_proposal_rejected") is True,
        "stale_revision_rejected": guards.get("stale_revision_rejected") is True,
        "duplicate_click_idempotent": guards.get("duplicate_click_idempotent") is True,
        "failed_reload_rolled_back": guards.get("failed_reload_rolled_back") is True,
    }
    return {"passed": all(checks.values()), "checks": checks}


def _phase(context: dict[str, Any], waf: Any, mode: str) -> dict[str, Any]:
    since = datetime.now(UTC).isoformat()
    applied = waf.apply_policy(dict(ACCEPTANCE_POLICY), mode)
    active = waf.wait_active(applied)
    if not active.get("active"):
        raise RuntimeError(f"{mode} rule did not become active")
    verification = verify(context)
    benign = run_benign_suite(context)
    events = waf.events(since=since, rule_ids=[RULE_IDS[mode]])
    return {
        "mode": mode,
        "apply": applied,
        "active": active,
        "verify": verification,
        "benign": benign,
        "waf_events": events,
    }


def evaluate(context: dict[str, Any]) -> dict[str, Any]:
    from pathlib import Path

    from .operation_lock import exclusive_operation

    state_dir = Path(context.get("state_dir", "/var/lib/gym/state"))
    with exclusive_operation(state_dir):
        return _evaluate_locked(context)


def _evaluate_locked(context: dict[str, Any]) -> dict[str, Any]:
    """Run baseline, LOG_ONLY, BLOCK, and removal tests with restoration.

    This function is intended only for the explicit active-evaluation command.
    It refuses to claim success when failure-injection callbacks are absent.
    """

    evidence_dir, _ = _validated_context(context)
    waf = context.get("waf_client")
    guards_runner: Callable[[dict[str, Any]], dict[str, bool]] | None = context.get(
        "failure_guards_runner"
    )
    report: dict[str, Any] = {
        "scenario": SCENARIO,
        "started_at": datetime.now(UTC).isoformat(),
        "baseline": {},
        "log_only": {},
        "block": {},
        "removal": {},
        "failure_guards": {},
    }
    if waf is None:
        report["error"] = "active evaluation requires the deterministic WAF client"
        result = {"passed": False, "checks": {"waf_client_available": False}}
    else:
        snapshot = waf.snapshot()
        try:
            report["baseline"] = {
                "scan": run_scan(context),
                "verify": verify(context),
                "benign": run_benign_suite(context),
            }
            report["log_only"] = _phase(context, waf, "LOG_ONLY")
            report["block"] = _phase(context, waf, "BLOCK")
            restored = waf.restore(snapshot)
            report["removal"] = {
                "restore": restored,
                "active": restored,
                "verify": verify(context),
                "benign": run_benign_suite(context),
            }
            if guards_runner is not None:
                report["failure_guards"] = guards_runner(context)
            result = assess_acceptance(report)
        except Exception as exc:  # restoration still runs; success is impossible
            report["error"] = f"active evaluation failed: {type(exc).__name__}"
            result = {"passed": False, "checks": {"evaluation_completed": False}}
        finally:
            try:
                restored = waf.restore(snapshot)
                if not restored.get("active"):
                    raise RuntimeError("final dataplane restoration was not observed")
                report["final_restore"] = {"status": "completed", "active": restored}
            except Exception as exc:
                report["final_restore"] = {
                    "status": "failed",
                    "error": type(exc).__name__,
                }
                result = {"passed": False, "checks": {"final_restore_completed": False}}

    report["finished_at"] = datetime.now(UTC).isoformat()
    report["assessment"] = result
    path = evidence_dir / SCENARIO / "acceptance" / f"{uuid.uuid4().hex}.json"
    _write_json(path, report)
    return {**result, "evidence": [str(path)], "report": report}
