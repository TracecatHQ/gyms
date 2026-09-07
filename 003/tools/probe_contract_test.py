#!/usr/bin/env python3
"""Offline contract tests for the constrained Gym 003 probe."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GYM_ROOT / "src"))

from gym_plugin import policy, probe, scanner, target_seed, traffic  # noqa: E402


class ProbeContractTests(unittest.TestCase):
    def test_target_command_and_paths_are_fixed(self) -> None:
        self.assertEqual(probe.INGRESS, "http://bunkerweb:8080")
        self.assertEqual(probe.FIXED_COMMAND, "printf gym-003-rce-ok")
        self.assertNotIn("command", probe.verify.__annotations__)
        self.assertNotIn("url", probe.verify.__annotations__)

    def test_context_rejects_caller_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(probe.ProbeError):
                probe._validated_context(
                    {"ingress": "http://example.invalid", "evidence_dir": directory}
                )

    def test_identity_is_read_from_small_fixed_capsule(self) -> None:
        self.assertEqual(
            probe._extract_auth_capsule(b'[{"id":"owner-id","hash":"auth-hash"}]'),
            ("owner-id", "auth-hash"),
        )
        self.assertFalse(hasattr(probe, "FIXED_DATABASE_PATH"))

    def test_forged_cookie_has_valid_hs256_signature_and_no_browser_binding(self) -> None:
        token = probe._forge_owner_cookie(("owner-id", "auth-hash"), "test-secret")
        signing_input, signature = token.rsplit(".", 1)
        expected = probe._b64url(
            hmac.new(b"test-secret", signing_input.encode(), hashlib.sha256).digest()
        )
        self.assertEqual(signature, expected)
        payload_part = signing_input.split(".", 1)[1]
        padding = "=" * (-len(payload_part) % 4)
        payload = json.loads(__import__("base64").urlsafe_b64decode(payload_part + padding))
        self.assertNotIn("browserId", payload)
        self.assertEqual(payload["id"], "owner-id")
        self.assertEqual(payload["hash"], "auth-hash")

    def test_seed_capsule_uses_only_fixed_builtin_nodes_and_path(self) -> None:
        workflow = target_seed._auth_capsule_workflow(("owner-id", "auth-hash"))
        node_types = {node["type"] for node in workflow["nodes"]}
        self.assertEqual(
            node_types,
            {
                "n8n-nodes-base.manualTrigger",
                "n8n-nodes-base.set",
                "n8n-nodes-base.convertToFile",
                "n8n-nodes-base.readWriteFile",
            },
        )
        write_node = next(node for node in workflow["nodes"] if node["name"].startswith("Write"))
        self.assertEqual(write_node["parameters"]["fileName"], target_seed.AUTH_CAPSULE_PATH)
        self.assertNotIn("executeCommand", json.dumps(workflow))

    def test_serialized_execution_marker_requires_exact_leaf(self) -> None:
        self.assertTrue(
            probe._find_marker(json.dumps({"runData": {"proof": probe.RCE_MARKER}}))
        )
        self.assertFalse(
            probe._find_marker(json.dumps({"expression": f"prefix {probe.RCE_MARKER}"}))
        )

    def test_n8n_jwt_fallback_secret_derivation(self) -> None:
        self.assertEqual(
            probe._jwt_secret(b'{"encryptionKey":"abcdef"}'),
            hashlib.sha256(b"ace").hexdigest(),
        )

    def test_nuclei_output_is_classified_as_suspicion(self) -> None:
        findings = scanner._parse_jsonl(
            json.dumps(
                {
                    "template-id": "CVE-2026-21858",
                    "matched-at": "http://bunkerweb:8080/signin",
                    "extracted-results": ["n8n Version: 1.65.0"],
                }
            )
        )
        self.assertEqual(findings[0]["classification"], "version_suspicion")

    def test_content_type_and_route_variants_are_present(self) -> None:
        self.assertIn("Application/JSON; charset=utf-8", probe.CONTENT_TYPE_VARIANTS)
        self.assertIn("/form/./supplier-intake", probe.ROUTE_VARIANTS)
        self.assertIn("/form/supplier-intake?source=gym003", probe.ROUTE_VARIANTS)
        self.assertIn("/FORM/supplier-intake", probe.ROUTE_VARIANTS)
        self.assertIn("/form/%73upplier-intake", probe.ROUTE_VARIANTS)
        self.assertIn("/form/supplier%2Dintake", probe.ROUTE_VARIANTS)
        self.assertIn("/form/supplier-intake%2F", probe.ROUTE_VARIANTS)
        self.assertIn(
            f"Multipart/Form-Data; boundary={traffic.UPLOAD_BOUNDARY}; charset=UTF-8",
            traffic.UPLOAD_CONTENT_TYPES,
        )

    def test_rule_canonicalizes_route_before_matching(self) -> None:
        proposal = policy.validate_proposal(
            {
                "scenario": policy.SCENARIO,
                "revision": policy.CURRENT_PROPOSAL_REVISION,
                "route": policy.ROUTE,
                "method": policy.METHOD,
                "allowed_content_type": policy.ALLOWED_TYPE,
            },
            expected_revision=policy.CURRENT_PROPOSAL_REVISION,
        )
        _, rule = policy.render_modsecurity(proposal, "BLOCK")
        self.assertIn("@rx (?i)^(?:/|%2f)(?:f|%66)", rule)
        self.assertIn("(?:s|%73)", rule)
        self.assertIn("(?:\\-|%2d)", rule)

    def test_failed_workflow_cleanup_makes_confirmed_execution_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def read_file(_session, path, **_kwargs):
                if path == probe.FIXED_CONFIG_PATH:
                    return 200, b"config"
                return 200, b"capsule"

            with (
                patch.object(probe, "_read_file", side_effect=read_file),
                patch.object(probe, "_jwt_secret", return_value="secret"),
                patch.object(
                    probe,
                    "_extract_auth_capsule",
                    return_value=("owner-id", "auth-hash"),
                ),
                patch.object(probe, "_forge_owner_cookie", return_value="cookie"),
                patch.object(
                    probe,
                    "_json_request",
                    side_effect=[
                        (201, {"id": "temporary-workflow"}),
                        (200, {"proof": probe.RCE_MARKER}),
                        (500, {}),
                    ],
                ),
            ):
                result = probe._verify_locked(
                    {
                        "evidence_dir": root / "evidence",
                        "state_dir": root / "state",
                    }
                )
                self.assertTrue(
                    (root / "state" / probe.SCENARIO / probe.DIRTY_FILE).exists()
                )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["cleanup"]["status"], "failed")
        self.assertEqual(result["error"], "temporary workflow cleanup was not confirmed")


if __name__ == "__main__":
    unittest.main()
