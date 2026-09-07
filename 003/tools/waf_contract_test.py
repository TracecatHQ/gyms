#!/usr/bin/env python3
"""Offline contracts for restoring an invalid managed WAF configuration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GYM_ROOT / "src"))

from gym_plugin.waf import CONFIG_PATH, WAFClient  # noqa: E402


class WAFContractTests(unittest.TestCase):
    def test_restore_replaces_a_persisted_invalid_config(self) -> None:
        client = WAFClient(
            "http://bw-api:8888",
            "gym-admin",
            "token",
            "http://bunkerweb:8080",
            Path("/tmp/unused-events"),
        )
        snapshot = {"schema_version": 1, "configs": [{"data": "valid rule"}]}
        responses = [
            (400, {"status": "error"}),
            (200, {"status": "success"}),
            (201, {"status": "success"}),
        ]
        with (
            patch.object(client, "_get", return_value={"data": "invalid rule"}),
            patch.object(client, "_api", side_effect=responses) as api,
            patch.object(client, "wait_active", return_value={"active": True}),
        ):
            result = client.restore(snapshot)

        self.assertTrue(result["restored"])
        self.assertEqual(
            [item.args[:2] for item in api.call_args_list],
            [("PATCH", CONFIG_PATH), ("DELETE", CONFIG_PATH), ("POST", "/configs")],
        )


if __name__ == "__main__":
    unittest.main()
