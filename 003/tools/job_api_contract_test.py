#!/usr/bin/env python3
"""Offline contracts for restart recovery and firewall result classification."""

from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GYM_ROOT / "src"))

from gym_plugin import job_api, probe, traffic, waf  # noqa: E402


class FakeWAF:
    def __init__(self, *, idempotent: bool) -> None:
        self.idempotent = idempotent
        self.restored = False

    def snapshot(self):
        return {"schema_version": 1, "configs": []}

    def apply_policy(self, _policy, _mode):
        return {"rule_id": 9300302, "idempotent": self.idempotent}

    def wait_active(self, _applied):
        return {"active": True}

    def events(self, _since, _rule_ids):
        return [{"rule_id": 9300302}]

    def restore(self, _snapshot):
        self.restored = True
        return {"active": True}


class JobAPIContractTests(unittest.TestCase):
    def test_restart_marks_orphaned_jobs_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.object(job_api, "STATE", state):
                job_api.write_record(
                    {
                        "run_id": "run-deadbeef",
                        "status": "running",
                        "verdict": None,
                    }
                )
                job_api.reconcile_interrupted_jobs()
                record = job_api.read_record("run-deadbeef")

        self.assertEqual(record["status"], "inconclusive")
        self.assertEqual(record["verdict"], "inconclusive")
        self.assertEqual(record["error"], "job interrupted by test API restart")

    def test_new_block_requires_pre_change_impact(self) -> None:
        client = FakeWAF(idempotent=False)
        with (
            patch.object(
                probe,
                "verify",
                side_effect=[
                    {"verdict": "not_reproduced"},
                    {"verdict": "blocked_by_waf"},
                ],
            ),
            patch.object(traffic, "run_benign_suite", return_value={"passed": True}),
            patch.object(waf.WAFClient, "from_env", return_value=client),
        ):
            with self.assertRaisesRegex(
                job_api.RuleApplicationError, "post-change"
            ) as raised:
                job_api.apply_rule(
                    {},
                    {
                        "mode": "BLOCK",
                        "proposal_revision": 1,
                    },
                )

        self.assertTrue(client.restored)
        self.assertEqual(
            raised.exception.result["rollback"],
            {"attempted": True, "succeeded": True},
        )
        self.assertEqual(raised.exception.result["benign"], {"passed": True})

    def test_failed_rule_job_persists_rollback_result(self) -> None:
        failure = job_api.RuleApplicationError(
            "post-change checks failed",
            {
                "rollback": {"attempted": True, "succeeded": True},
                "benign": {"passed": False},
                "waf_events": [],
            },
        )
        record = {
            "run_id": "run-deadbeef",
            "kind": "apply_rule",
            "scenario": "supplier-intake",
            "status": "queued",
        }
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(job_api, "STATE", Path(directory) / "jobs"),
                patch.object(job_api, "_dispatch", side_effect=failure),
                patch("gym_plugin.evidence_store.upload_job", return_value=[]),
            ):
                job_api.run_job(record, {})
                persisted = job_api.read_record("run-deadbeef")

        self.assertEqual(persisted["status"], "inconclusive")
        self.assertEqual(
            persisted["rollback"], {"attempted": True, "succeeded": True}
        )

    def test_duplicate_submission_does_not_wait_for_running_rule(self) -> None:
        request = {
            "kind": "apply_rule",
            "scenario": "supplier-intake",
            "case_id": "case-1",
            "proposal_revision": 1,
            "mode": "BLOCK",
        }
        idempotency_key = "supplier-intake|case-1|1|BLOCK"
        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_execution_lock() -> None:
            with job_api.LOCK:
                lock_held.set()
                release_lock.wait(timeout=2)

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.object(job_api, "STATE", state):
                job_api.write_record(
                    {
                        "run_id": "run-deadbeef",
                        "kind": "apply_rule",
                        "scenario": "supplier-intake",
                        "case_id": "case-1",
                        "status": "running",
                        "idempotency_key": idempotency_key,
                    }
                )
                holder = threading.Thread(target=hold_execution_lock)
                holder.start()
                self.assertTrue(lock_held.wait(timeout=1))
                started = time.monotonic()
                try:
                    result = job_api.submit(request)
                finally:
                    release_lock.set()
                    holder.join(timeout=2)

        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(result["run_id"], "run-deadbeef")

    def test_idempotent_existing_block_can_be_rechecked(self) -> None:
        client = FakeWAF(idempotent=True)
        with (
            patch.object(
                probe,
                "verify",
                side_effect=[
                    {"verdict": "blocked_by_waf"},
                    {"verdict": "blocked_by_waf"},
                ],
            ),
            patch.object(traffic, "run_benign_suite", return_value={"passed": True}),
            patch.object(waf.WAFClient, "from_env", return_value=client),
        ):
            result = job_api.apply_rule(
                {},
                {
                    "mode": "BLOCK",
                    "proposal_revision": 1,
                },
            )

        self.assertEqual(result["verdict"], "mitigated at tested ingress")
        self.assertFalse(client.restored)


if __name__ == "__main__":
    unittest.main()
