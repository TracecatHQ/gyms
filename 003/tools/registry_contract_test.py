#!/usr/bin/env python3
"""Offline contracts for Gym 003's Tracecat local registry actions."""

from __future__ import annotations

import importlib.util
import inspect
import json
import sys
import tempfile
import time
import tomllib
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import get_args, get_type_hints
from unittest.mock import patch


GYM_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_ROOT = GYM_ROOT / "local_registry"
ACTION_FILE = REGISTRY_ROOT / "local_registry/supplier_intake.py"
sys.path.insert(0, str(GYM_ROOT / "src"))
ACTION_NAMES = {
    "security.supplier_intake.scan",
    "security.supplier_intake.verify",
    "security.supplier_intake.propose_policy",
    "security.supplier_intake.apply_reviewed_policy",
}


class _Registry:
    def __init__(self) -> None:
        self.actions: dict[str, dict] = {}

    def register(self, **metadata):
        def decorator(function):
            name = f"{metadata['namespace']}.{function.__name__}"
            self.actions[name] = {"function": function, **metadata}
            return function

        return decorator


class _RegistrySecret:
    def __init__(self, *, name: str, keys: list[str]) -> None:
        self.name = name
        self.keys = keys


def _load_actions():
    registry = _Registry()
    tracecat_registry = types.ModuleType("tracecat_registry")
    tracecat_registry.RegistrySecret = _RegistrySecret
    tracecat_registry.ctx = types.SimpleNamespace(cases=types.SimpleNamespace())
    tracecat_registry.registry = registry
    previous = sys.modules.get("tracecat_registry")
    sys.modules["tracecat_registry"] = tracecat_registry
    try:
        spec = importlib.util.spec_from_file_location("gym_003_registry", ACTION_FILE)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {ACTION_FILE}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop("tracecat_registry", None)
        else:
            sys.modules["tracecat_registry"] = previous
    return module, registry.actions


class RegistryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module, cls.actions = _load_actions()

    def test_exactly_four_bounded_actions_are_registered(self):
        self.assertEqual(set(self.actions), ACTION_NAMES)
        for name, action in self.actions.items():
            self.assertEqual(action["namespace"], "security.supplier_intake")
            self.assertTrue(action["description"].strip(), name)
        self.assertIn(
            "supplier-intake-actions-v4",
            self.actions["security.supplier_intake.scan"]["description"],
        )

    def test_scan_and_verify_accept_only_a_case_identifier(self):
        for name in (
            "security.supplier_intake.scan",
            "security.supplier_intake.verify",
        ):
            signature = inspect.signature(self.actions[name]["function"])
            self.assertEqual(list(signature.parameters), ["case_id"])

    def test_policy_inputs_are_constrained_and_application_requires_approval(self):
        hints = get_type_hints(
            self.actions["security.supplier_intake.propose_policy"]["function"],
            globalns=vars(self.module),
        )
        self.assertEqual(get_args(hints["route"]), ("/form/supplier-intake",))
        self.assertEqual(get_args(hints["method"]), ("POST",))
        self.assertEqual(
            get_args(hints["allowed_content_type"]),
            ("multipart/form-data",),
        )
        self.assertEqual(
            set(get_args(hints["recommended_mode"])),
            {"BLOCK", "LOG_ONLY"},
        )

        apply = self.actions["security.supplier_intake.apply_reviewed_policy"]
        self.assertIs(apply["requires_approval"], True)
        self.assertEqual(
            list(inspect.signature(apply["function"]).parameters),
            ["case_id", "task_id", "proposal_revision", "mode"],
        )
        self.assertEqual(
            {secret.name for secret in apply["secrets"]},
            {"supplier_intake_n8n", "supplier_intake_waf"},
        )

    def test_agent_can_investigate_and_propose_but_cannot_apply(self):
        preset = json.loads(
            (GYM_ROOT / "benchmark/agent/analyst-preset.json").read_text()
        )
        actions = set(preset["actions"])
        self.assertEqual(
            actions & ACTION_NAMES,
            ACTION_NAMES - {"security.supplier_intake.apply_reviewed_policy"},
        )
        self.assertNotIn("core.workflow.execute", actions)

    def test_local_registry_package_has_only_exact_dependency_pins(self):
        pyproject = tomllib.loads((REGISTRY_ROOT / "pyproject.toml").read_text())
        requirements = [
            *pyproject["build-system"].get("requires", []),
            *pyproject["project"].get("dependencies", []),
        ]
        self.assertTrue(requirements)
        for requirement in requirements:
            self.assertIn("==", requirement, requirement)
            self.assertNotIn(">=", requirement, requirement)
            self.assertNotIn("~=", requirement, requirement)

    def test_registry_actions_do_not_expose_arbitrary_execution_inputs(self):
        source = ACTION_FILE.read_text()
        for forbidden in (
            "subprocess",
            "shell=True",
            "target:",
            "template:",
            "command:",
            "headers:",
        ):
            self.assertNotIn(forbidden, source)

    def test_proposal_rejects_unrelated_case_without_persisting(self):
        updates = []
        previous_cases = self.module.ctx.cases
        self.module.ctx.cases = types.SimpleNamespace(
            get_case=lambda case_id: {
                "id": case_id,
                "payload": {
                    "gym_id": "unmanaged",
                    "dedup_key": "another|asset|CVE",
                    "scenario": "another-scenario",
                    "asset": "another.example",
                    "cve": "CVE-0000-0000",
                },
            },
            update_case_simple=lambda *args, **kwargs: updates.append((args, kwargs)),
        )
        try:
            propose = self.actions[
                "security.supplier_intake.propose_policy"
            ]["function"]
            with tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(
                        self.module,
                        "_execution_context",
                        return_value={"state_dir": Path(directory)},
                    ),
                    self.assertRaisesRegex(
                        ValueError, "not the managed supplier intake incident"
                    ),
                ):
                    propose(
                        case_id="unrelated-case",
                        recommended_mode="BLOCK",
                        rationale="This rationale is long enough to pass validation.",
                    )
        finally:
            self.module.ctx.cases = previous_cases

        self.assertEqual(updates, [])

    def test_concurrent_proposals_cannot_overwrite_each_other(self):
        case_id = "managed-case"
        stored_payload = {
            "gym_id": "003",
            "dedup_key": "supplier-intake|supplier.intake.test|CVE-2026-21858",
            "scenario": "supplier-intake",
            "asset": "supplier.intake.test",
            "cve": "CVE-2026-21858",
        }
        updates = []

        def get_case(requested_case_id):
            snapshot = dict(stored_payload)
            time.sleep(0.02)
            return {"id": requested_case_id, "payload": snapshot}

        def update_case_simple(_case_id, *, payload):
            stored_payload.clear()
            stored_payload.update(payload)
            updates.append(payload["firewall_proposal"]["proposal_id"])

        previous_cases = self.module.ctx.cases
        self.module.ctx.cases = types.SimpleNamespace(
            get_case=get_case,
            update_case_simple=update_case_simple,
        )
        propose = self.actions["security.supplier_intake.propose_policy"]["function"]
        try:
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(
                    self.module,
                    "_execution_context",
                    return_value={"state_dir": Path(directory)},
                ):
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures = [
                            pool.submit(
                                propose,
                                case_id=case_id,
                                recommended_mode=mode,
                                rationale=f"Use the reviewed {mode} policy for this incident.",
                            )
                            for mode in ("BLOCK", "LOG_ONLY")
                        ]
                    outcomes = []
                    for future in futures:
                        try:
                            outcomes.append(future.result())
                        except ValueError as exc:
                            outcomes.append(exc)
        finally:
            self.module.ctx.cases = previous_cases

        self.assertEqual(len(updates), 1)
        self.assertEqual(sum(isinstance(value, dict) for value in outcomes), 1)
        self.assertEqual(sum(isinstance(value, ValueError) for value in outcomes), 1)

    def test_tracecat_executor_hosts_the_registry_without_a_job_api_sidecar(self):
        compose = (GYM_ROOT / "compose.override.yml").read_text()
        dockerfile = (GYM_ROOT / "images/control/Dockerfile").read_text()
        self.assertNotIn("test-api:", compose)
        self.assertNotIn("internal-test-api", compose)
        self.assertIn('command: ["-m", "tracecat.executor.worker"]', compose)
        self.assertIn("networks: [core, core-db, temporal, test-traffic, management]", compose)
        self.assertIn("- gym-jobs:/var/lib/gym", compose)
        self.assertIn("COPY --chown=apiuser:apiuser local_registry/ /app/local_registry/", dockerfile)
        self.assertIn("/app/local_registry", dockerfile)


if __name__ == "__main__":
    unittest.main()
