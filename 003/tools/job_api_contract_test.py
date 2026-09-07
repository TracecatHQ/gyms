#!/usr/bin/env python3
"""Offline contracts for restart recovery and firewall result classification."""

from __future__ import annotations

import sys
import tempfile
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
            with self.assertRaisesRegex(RuntimeError, "post-change"):
                job_api.apply_rule(
                    {},
                    {
                        "mode": "BLOCK",
                        "proposal_revision": 1,
                    },
                )

        self.assertTrue(client.restored)

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
