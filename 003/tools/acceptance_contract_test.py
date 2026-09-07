#!/usr/bin/env python3
"""Offline tests that ensure failure states cannot be graded as success."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GYM_ROOT / "src"))

from gym_plugin.acceptance import RULE_IDS, _safe_terminal, assess_acceptance  # noqa: E402


def benign() -> dict:
    return {
        "passed": True,
        "transactions": [
            {"name": "supplier_upload", "status": 200},
            {"name": "order_update_downstream_receipt", "status": 200},
            {"name": "staff_authentication", "status": 200},
            {"name": "health_check", "status": 200},
        ],
    }


class AcceptanceContractTests(unittest.TestCase):
    def complete_report(self) -> dict:
        return {
            "baseline": {
                "scan": {"verdict": "suspected_vulnerable_version"},
                "verify": {"verdict": "confirmed_rce"},
                "benign": benign(),
            },
            "log_only": {
                "verify": {"verdict": "confirmed_rce"},
                "benign": benign(),
                "waf_events": [{"rule_id": RULE_IDS["LOG_ONLY"], "action": "log"}],
            },
            "block": {
                "verify": {"verdict": "blocked_by_waf"},
                "benign": benign(),
                "waf_events": [{"rule_id": RULE_IDS["BLOCK"], "action": "deny"}],
            },
            "removal": {"verify": {"verdict": "confirmed_rce"}},
            "failure_guards": {
                "outage_not_success": True,
                "malformed_proposal_rejected": True,
                "stale_revision_rejected": True,
                "duplicate_click_idempotent": True,
                "failed_reload_rolled_back": True,
            },
        }

    def test_complete_report_passes(self) -> None:
        self.assertTrue(assess_acceptance(self.complete_report())["passed"])

    def test_each_required_check_is_fail_closed(self) -> None:
        report = self.complete_report()
        report["failure_guards"]["stale_revision_rejected"] = False
        assessed = assess_acceptance(report)
        self.assertFalse(assessed["passed"])
        self.assertFalse(assessed["checks"]["stale_revision_rejected"])

    def test_outage_timeout_and_malformed_are_never_terminal_success(self) -> None:
        self.assertFalse(_safe_terminal({"status": "timed_out", "verdict": "confirmed_rce"}))
        self.assertFalse(_safe_terminal({"status": "completed", "verdict": "inconclusive"}))
        self.assertFalse(_safe_terminal({"status": "completed", "error": "reload failed"}))
        self.assertFalse(_safe_terminal(None))

    def test_benign_status_regression_fails(self) -> None:
        report = self.complete_report()
        report["block"]["benign"]["transactions"][0]["status"] = 403
        self.assertFalse(assess_acceptance(report)["passed"])

    def test_missing_correlated_event_fails(self) -> None:
        report = self.complete_report()
        report["block"]["waf_events"] = []
        self.assertFalse(assess_acceptance(report)["passed"])


if __name__ == "__main__":
    unittest.main()
