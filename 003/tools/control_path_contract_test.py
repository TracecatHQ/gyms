#!/usr/bin/env python3
"""Contracts for the reviewed firewall control path and read-only status."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(GYM_ROOT / "src"), str(GYM_ROOT.parent / "src")]

from gym_plugin import host, reconcile, rule_application  # noqa: E402


class _FakeWAF:
    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.event_boundary: str | None = None
        self.event_calls = 0

    def snapshot(self):
        return {"schema_version": 1, "configs": []}

    def apply_policy(self, _policy, _mode):
        return {"rule_id": 9300302, "idempotent": False}

    def wait_active(self, _applied):
        self.order.append("active")
        return {"active": True}

    def events(self, since, _rule_ids):
        self.order.append("events")
        self.event_boundary = since
        self.event_calls += 1
        return [
            {
                "unique_id": "activation" if self.event_calls == 1 else "verification",
                "rule_id": 9300302,
                "audit_correlated": True,
                "blocked": True,
            }
        ]

    def restore(self, _snapshot):
        return {"active": True}


class _FixedNow:
    @classmethod
    def now(cls, _timezone):
        return cls()

    def isoformat(self):
        return "2026-09-07T10:00:00+00:00"

    def replace(self, **_kwargs):
        return self


class _InactiveWAF(_FakeWAF):
    def wait_active(self, _applied):
        self.order.append("active")
        return {"active": False}


class _FailedRollbackWAF(_InactiveWAF):
    def restore(self, _snapshot):
        raise RuntimeError("password=must-not-reach-evidence")


class ControlPathContractTests(unittest.TestCase):
    def test_info_does_not_print_tenant_password(self):
        output = io.StringIO()
        with (
            patch.object(
                host.config,
                "parse_env",
                return_value={
                    "TRACEcat_TENANT_EMAIL": "analyst@example.test",
                    "TRACEcat_TENANT_PASSWORD": "must-not-be-printed",
                },
            ),
            redirect_stdout(output),
        ):
            host.info()

        rendered = output.getvalue()
        self.assertIn("Tenant email: analyst@example.test", rendered)
        self.assertNotIn("must-not-be-printed", rendered)

    def test_waf_events_begin_at_post_activation_verification_boundary(self):
        order: list[str] = []
        waf = _FakeWAF(order)

        def verify(_context):
            phase = "before" if "active" not in order else "after"
            order.append(phase)
            return {
                "verdict": "confirmed_rce" if phase == "before" else "blocked_by_waf"
            }

        with (
            patch("gym_plugin.probe.verify", side_effect=verify),
            patch(
                "gym_plugin.traffic.run_benign_suite",
                return_value={"passed": True, "transactions": []},
            ),
            patch("gym_plugin.waf.WAFClient.from_env", return_value=waf),
            patch.object(rule_application, "datetime", _FixedNow),
        ):
            result = rule_application.apply_rule(
                {"started_at": "too-early"},
                {
                    "mode": "BLOCK",
                    "proposal_revision": 1,
                    "proposal": {
                        "scenario": "supplier-intake",
                        "revision": 1,
                        "route": "/form/supplier-intake",
                        "method": "POST",
                        "allowed_content_type": "multipart/form-data",
                    },
                },
            )

        self.assertEqual(result["verdict"], "mitigated at tested ingress")
        self.assertEqual(order, ["before", "active", "events", "after", "events"])
        self.assertEqual(waf.event_boundary, "2026-09-07T10:00:00+00:00")

    def test_post_change_failure_returns_sanitized_rollback_evidence(self):
        order: list[str] = []
        waf = _InactiveWAF(order)

        with (
            patch(
                "gym_plugin.probe.verify",
                return_value={"verdict": "confirmed_rce"},
            ),
            patch("gym_plugin.waf.WAFClient.from_env", return_value=waf),
        ):
            result = rule_application.apply_rule(
                {},
                {
                    "mode": "BLOCK",
                    "proposal_revision": 1,
                    "proposal": {
                        "scenario": "supplier-intake",
                        "revision": 1,
                        "route": "/form/supplier-intake",
                        "method": "POST",
                        "allowed_content_type": "multipart/form-data",
                    },
                },
            )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(
            result["error"],
            "control verification failed; prior firewall state restored",
        )
        self.assertEqual(result["rollback"], {"attempted": True, "succeeded": True})
        self.assertEqual(order, ["active"])

    def test_rollback_failure_does_not_expose_underlying_error(self):
        with (
            patch(
                "gym_plugin.probe.verify",
                return_value={"verdict": "confirmed_rce"},
            ),
            patch(
                "gym_plugin.waf.WAFClient.from_env",
                return_value=_FailedRollbackWAF([]),
            ),
        ):
            result = rule_application.apply_rule(
                {},
                {
                    "mode": "BLOCK",
                    "proposal_revision": 1,
                    "proposal": {
                        "scenario": "supplier-intake",
                        "revision": 1,
                        "route": "/form/supplier-intake",
                        "method": "POST",
                        "allowed_content_type": "multipart/form-data",
                    },
                },
            )

        self.assertEqual(result["error"], "control verification failed; rollback failed")
        self.assertEqual(result["rollback"], {"attempted": True, "succeeded": False})
        self.assertNotIn("must-not-reach-evidence", repr(result))

    def test_status_case_check_rejects_presentation_drift_without_patch(self):
        desired = reconcile.desired_case()
        actual = {
            "id": "case-id",
            **desired,
            "summary": "drifted summary",
        }
        with (
            patch.object(
                reconcile,
                "list_managed_cases",
                return_value=[{"id": "case-id", "payload": desired["payload"]}],
            ),
            patch.object(reconcile, "request", return_value=actual) as request,
        ):
            with self.assertRaisesRegex(
                reconcile.ReconcileError, "presentation has drifted; run reconcile"
            ):
                reconcile.reconcile_case(None, "workspace", create_missing=False)

        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[1], "GET")


if __name__ == "__main__":
    unittest.main()
