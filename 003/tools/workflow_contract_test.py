#!/usr/bin/env python3
"""Offline contracts for agent permissions and retirement of the wrapper."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(GYM_ROOT / "src"), str(GYM_ROOT.parent / "src")]

from gym_plugin import workflows  # noqa: E402


class WorkflowAPI:
    """Published desired workflows plus optional historical rows."""

    def __init__(self, extra=(), *, ignore_delete=False):
        self.rows = []
        self.definitions = {}
        self.deletions = []
        self.ignore_delete = ignore_delete
        for spec in workflows.WORKFLOW_SPECS:
            doc = workflows.load_definition(spec)
            row = {
                "id": doc["workflow_id"],
                "title": doc["definition"]["title"],
                "alias": spec.alias,
                "version": 1,
                "status": "online",
            }
            self.rows.append(row)
            self.definitions[row["id"]] = workflows._persisted_definition(doc["definition"])
        self.rows.extend(copy.deepcopy(extra))

    def request(self, _client, method, url, **kwargs):
        base = "/workspaces/workspace/workflows"
        if method == "GET" and url == base:
            return {"items": copy.deepcopy(self.rows)}
        tail = url.removeprefix(base + "/")
        if method == "GET" and tail.endswith("/definition"):
            return {"content": copy.deepcopy(self.definitions[tail.removesuffix("/definition")])}
        if method == "GET":
            return copy.deepcopy(next(row for row in self.rows if row["id"] == tail))
        if method == "DELETE":
            assert kwargs["expected"] == (204,)
            self.deletions.append(tail)
            if not self.ignore_delete:
                self.rows = [row for row in self.rows if row["id"] != tail]
            return None
        raise AssertionError(f"unexpected mutation: {method} {url}")


def retired(**overrides):
    return {
        "id": workflows.RETIRED_INVESTIGATION_ID,
        "title": workflows.RETIRED_INVESTIGATION_TITLE,
        "alias": workflows.RETIRED_INVESTIGATION_ALIAS,
    } | overrides


class WorkflowContractTests(unittest.TestCase):
    def test_three_fixtures_and_idempotent_retirement(self):
        self.assertEqual(
            {spec.filename for spec in workflows.WORKFLOW_SPECS},
            {"scan.json", "verification.json", "rule-application.json"},
        )
        self.assertEqual(
            {path.name for path in workflows.WORKFLOW_DIR.glob("*.json")},
            {spec.filename for spec in workflows.WORKFLOW_SPECS},
        )
        api = WorkflowAPI([retired()])
        for _ in range(2):
            actual = workflows.reconcile_workflows(None, "workspace", api.request)
            self.assertEqual(len(actual), 3)
            self.assertEqual(len(api.rows), 3)
            self.assertEqual(len(workflows.verify_workflows(None, "workspace", api.request)), 3)
        self.assertEqual(api.deletions, [workflows.RETIRED_INVESTIGATION_ID])

    def test_stable_id_handles_renamed_wrapper(self):
        api = WorkflowAPI([retired(alias=None, title="Old wrapper")])
        workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertEqual(api.deletions, [workflows.RETIRED_INVESTIGATION_ID])

    def test_exact_name_and_alias_handle_legacy_import_id(self):
        api = WorkflowAPI([retired(id="legacy-import")])
        workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertEqual(api.deletions, ["legacy-import"])

    def test_title_or_alias_collision_prevents_any_deletion(self):
        for overrides in (
            {"id": "unrelated", "alias": None},
            {"id": "unrelated", "title": "User workflow"},
        ):
            with self.subTest(overrides=overrides):
                api = WorkflowAPI([retired(), retired(**overrides)])
                with self.assertRaisesRegex(workflows.WorkflowError, "ambiguous"):
                    workflows.reconcile_workflows(None, "workspace", api.request)
                self.assertEqual(api.deletions, [])

    def test_unrelated_workflows_are_preserved(self):
        unrelated = {"id": "unrelated", "title": "User workflow", "alias": "user-workflow"}
        api = WorkflowAPI([retired(), unrelated])
        workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertIn(unrelated, api.rows)

    def test_delete_must_be_visible_in_inventory(self):
        api = WorkflowAPI([retired()], ignore_delete=True)
        with self.assertRaisesRegex(workflows.WorkflowError, "remains after deletion"):
            workflows.reconcile_workflows(None, "workspace", api.request)

    def test_status_rejects_obsolete_wrapper_without_mutation(self):
        api = WorkflowAPI([retired()])
        with self.assertRaisesRegex(workflows.WorkflowError, "run reconcile"):
            workflows.verify_workflows(None, "workspace", api.request)
        self.assertEqual(api.deletions, [])

    def test_two_presets_keep_verification_out_of_analyst(self):
        agent_dir = GYM_ROOT / "benchmark/agent"
        self.assertEqual(len(list(agent_dir.glob("*-preset.json"))), 2)
        analyst = json.loads((agent_dir / "mitigation-analyst-preset.json").read_text())
        verifier = json.loads((agent_dir / "attack-surface-preset.json").read_text())
        self.assertNotIn("core.workflow.execute", analyst["actions"])
        self.assertNotIn("core.workflow.execute", analyst["tool_approvals"])
        self.assertEqual(analyst["namespaces"], [])
        self.assertEqual(analyst["mcp_integrations"], [])
        self.assertFalse(analyst["agents"]["enabled"])
        self.assertEqual(
            verifier["actions"],
            ["core.cases.list_comments", "core.workflow.execute"],
        )
        self.assertIs(
            verifier["tool_approvals"]["core.cases.list_comments"], False
        )
        self.assertIs(verifier["tool_approvals"]["core.workflow.execute"], False)
        verifier_prompt = (agent_dir / verifier["prompt_file"]).read_text()
        self.assertIn("same workflow and execution identifiers", verifier_prompt)
        self.assertIn("Never retry the workflow", verifier_prompt)
        prompt = (agent_dir / analyst["prompt_file"]).read_text()
        self.assertIn("Attack Surface Verifier", prompt)
        self.assertIn("Test exploitability", prompt)
        self.assertIn("cannot execute workflows", prompt)


if __name__ == "__main__":
    unittest.main()
