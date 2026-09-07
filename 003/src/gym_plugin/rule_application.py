"""Atomic application of the reviewed supplier intake firewall policy."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import Any

from .policy import CURRENT_PROPOSAL_REVISION, validate_proposal


LOCK = threading.RLock()


class RuleApplicationError(RuntimeError):
    """Rule application failed after recording deterministic rollback evidence."""

    def __init__(self, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = result


def apply_rule(context: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Apply the validated policy and prove the resulting data-plane behavior."""

    from .probe import verify
    from .traffic import run_benign_suite
    from .waf import WAFClient

    mode = str(request.get("mode", "")).upper()
    if mode not in {"BLOCK", "LOG_ONLY"}:
        raise ValueError("rule mode must be BLOCK or LOG_ONLY")
    revision = int(request.get("proposal_revision", 0))
    if revision != CURRENT_PROPOSAL_REVISION:
        raise ValueError("stale proposal revision")
    proposal = request.get("proposal")
    if not isinstance(proposal, dict):
        raise ValueError("an exact persisted proposal is required")
    policy = validate_proposal(proposal, expected_revision=CURRENT_PROPOSAL_REVISION)
    client = WAFClient.from_env()
    with LOCK:
        before: dict[str, Any] = {}
        after: dict[str, Any] = {}
        benign: dict[str, Any] = {"passed": False}
        events: list[dict[str, Any]] = []
        snapshot: dict[str, Any] | None = None
        applied: dict[str, Any] | None = None
        rollback = {"attempted": False, "succeeded": None}
        try:
            before = verify(context)
            snapshot = client.snapshot()
            applied = client.apply_policy(policy.as_dict(), mode)
            activation = client.wait_active(applied)
            if not activation.get("active"):
                raise RuntimeError("BunkerWeb did not activate the proposed rule")
            # Collector timestamps have one-second precision. Take an explicit
            # post-activation ID baseline, then use a second-aligned boundary so
            # a fresh event in the current second is not lost to truncation.
            existing_event_ids = {
                str(event.get("unique_id"))
                for event in client.events(0, [applied["rule_id"]])
            }
            verification_started_at = datetime.now(UTC).replace(
                microsecond=0
            ).isoformat()
            after = verify(context)
            benign = run_benign_suite(context)
            # The audit collector writes asynchronously. Poll only inside the
            # post-activation window so activation probes cannot satisfy this
            # gate while the real verification event still has time to arrive.
            event_deadline = time.monotonic() + 5
            while True:
                events = [
                    event
                    for event in client.events(
                        verification_started_at,
                        [applied["rule_id"]],
                    )
                    if str(event.get("unique_id")) not in existing_event_ids
                ]
                if events or time.monotonic() >= event_deadline:
                    break
                time.sleep(0.25)
            benign_ok = benign.get("passed") is True
            if mode == "BLOCK":
                prior = before.get("verdict")
                success = (
                    (
                        prior in {"confirmed_file_read", "confirmed_rce"}
                        or (prior == "blocked_by_waf" and applied.get("idempotent") is True)
                    )
                    and after.get("verdict") == "blocked_by_waf"
                    and bool(events)
                    and benign_ok
                )
            else:
                success = (
                    after.get("verdict")
                    in {"confirmed_file_read", "confirmed_rce", "blocked_by_waf"}
                    and bool(events)
                    and benign_ok
                )
            if not success:
                raise RuntimeError(
                    "post-change attack, event correlation, or benign checks failed"
                )
            return {
                "verdict": (
                    "mitigated at tested ingress"
                    if mode == "BLOCK"
                    else (
                        "logging active; existing block preserved"
                        if after.get("verdict") == "blocked_by_waf"
                        else "observed, not blocked"
                    )
                ),
                "rule_id": applied["rule_id"],
                "proposal_revision": revision,
                "mode": mode,
                "before_verdict": before.get("verdict"),
                "after_verdict": after.get("verdict"),
                "benign": benign,
                "waf_events": [
                    {
                        "timestamp": event.get("timestamp"),
                        "rule_id": event.get("rule_id"),
                        "mode": event.get("mode"),
                        "audit_correlated": event.get("audit_correlated") is True,
                        "blocked": event.get("blocked") is True,
                    }
                    for event in events
                    if isinstance(event, dict)
                ],
                "rollback": rollback,
            }
        except Exception as exc:
            failure_message = str(exc)
            if snapshot is not None:
                rollback["attempted"] = True
                try:
                    restored = client.restore(snapshot)
                    rollback["succeeded"] = bool(restored.get("active"))
                except Exception:
                    rollback["succeeded"] = False
                if not rollback["succeeded"]:
                    failure_message = "rule operation failed and rollback failed"
            result = {
                "verdict": "inconclusive",
                "rule_id": (applied or {}).get("rule_id"),
                "proposal_revision": revision,
                "mode": mode,
                "before_verdict": before.get("verdict"),
                "after_verdict": after.get("verdict"),
                "benign": benign,
                "waf_events": [
                    {
                        "timestamp": event.get("timestamp"),
                        "rule_id": event.get("rule_id"),
                        "mode": event.get("mode"),
                        "audit_correlated": event.get("audit_correlated") is True,
                        "blocked": event.get("blocked") is True,
                    }
                    for event in events
                    if isinstance(event, dict)
                ],
                "rollback": rollback,
            }
            raise RuleApplicationError(failure_message, result) from exc
