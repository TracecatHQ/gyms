#!/usr/bin/env python3
"""Offline contracts for the Tracecat-native Agent and firewall workflow."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(GYM_ROOT / "src"), str(GYM_ROOT.parent / "src")]

from gym_plugin import reconcile, workflows  # noqa: E402


class WorkflowAPI:
    def __init__(self, extra=(), *, ignore_delete=False):
        self.rows: list[dict] = []
        self.definitions: dict[str, dict] = {}
        self.deletions: list[str] = []
        self.ignore_delete = ignore_delete
        for spec in workflows.WORKFLOW_SPECS:
            document = workflows.load_definition(spec)
            row = {
                "id": document["workflow_id"],
                "title": document["definition"]["title"],
                "alias": spec.alias,
                "version": 1,
                "status": "online",
            }
            self.rows.append(row)
            self.definitions[row["id"]] = workflows._persisted_definition(
                document["definition"]
            )
            self._set_graph(row["id"], positioned=False)
        self.rows.extend(copy.deepcopy(extra))

    def _set_graph(self, workflow_id, *, positioned):
        self.graph = getattr(self, "graph", {})
        self.graph[workflow_id] = {
            "actions": {
                "action-apply": {
                    "id": "action-apply",
                    "ref": "apply_reviewed_rule",
                    "position_x": 0.0,
                    "position_y": 300.0 if positioned else 0.0,
                },
                "action-record": {
                    "id": "action-record",
                    "ref": "record_rule_result",
                    "position_x": 0.0,
                    "position_y": 600.0 if positioned else 0.0,
                },
            },
            "trigger_position_x": 0.0,
            "trigger_position_y": 0.0,
        }

    def request(self, _client, method, url, **kwargs):
        base = "/workspaces/workspace/workflows"
        if method == "POST" and url == "/workspaces/workspace/actions/batch-positions":
            workflow_id = kwargs["params"]["workflow_id"]
            graph = self.graph[workflow_id]
            by_id = {action["id"]: action for action in graph["actions"].values()}
            for item in kwargs["body"]["actions"]:
                action = by_id[item["action_id"]]
                action["position_x"] = item["position"]["x"]
                action["position_y"] = item["position"]["y"]
            graph["trigger_position_x"] = kwargs["body"]["trigger_position"]["x"]
            graph["trigger_position_y"] = kwargs["body"]["trigger_position"]["y"]
            return None
        if method == "GET" and url == base:
            return {"items": copy.deepcopy(self.rows)}
        tail = url.removeprefix(base + "/")
        if method == "GET" and tail.endswith("/definition"):
            return {"content": copy.deepcopy(self.definitions[tail.removesuffix("/definition")])}
        if method == "GET":
            row = copy.deepcopy(next(row for row in self.rows if row["id"] == tail))
            row.update(copy.deepcopy(self.graph[tail]))
            return row
        if method == "DELETE":
            self.deletions.append(tail)
            if not self.ignore_delete:
                self.rows = [row for row in self.rows if row["id"] != tail]
            return None
        if method == "PATCH":
            next(row for row in self.rows if row["id"] == tail).update(kwargs["body"])
            return None
        if method == "POST" and tail.endswith("/commit"):
            next(row for row in self.rows if row["id"] == tail.removesuffix("/commit"))["version"] = 1
            return {"status": "success"}
        raise AssertionError(f"unexpected request: {method} {url}")


class WorkflowContractTests(unittest.TestCase):
    def test_one_human_workflow_and_three_retired_wrappers(self):
        self.assertEqual([spec.filename for spec in workflows.WORKFLOW_SPECS], ["rule-application.json"])
        self.assertEqual([spec.alias for spec in workflows.WORKFLOW_SPECS], [None])
        self.assertEqual(len(workflows.RETIRED_WORKFLOWS), 3)
        api = WorkflowAPI(
            [
                {"id": stable_id, "alias": alias, "title": title}
                for stable_id, alias, title in workflows.RETIRED_WORKFLOWS
            ]
        )
        actual = workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertEqual(set(actual), {"gym-003-rule-application"})
        self.assertEqual(len(api.rows), 1)
        self.assertEqual(len(api.deletions), 3)
        self.assertEqual(len(workflows.verify_workflows(None, "workspace", api.request)), 1)

    def test_unrelated_workflows_are_preserved(self):
        unrelated = {"id": "unrelated", "title": "User workflow", "alias": "user-workflow"}
        api = WorkflowAPI([unrelated])
        workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertIn(unrelated, api.rows)

    def test_status_rejects_retired_workflow_without_mutation(self):
        stable_id, alias, title = workflows.RETIRED_WORKFLOWS[0]
        api = WorkflowAPI([{"id": stable_id, "alias": alias, "title": title}])
        with self.assertRaisesRegex(workflows.WorkflowError, "run reconcile"):
            workflows.verify_workflows(None, "workspace", api.request)
        self.assertEqual(api.deletions, [])

    def test_delete_must_be_visible(self):
        stable_id, alias, title = workflows.RETIRED_WORKFLOWS[0]
        api = WorkflowAPI(
            [{"id": stable_id, "alias": alias, "title": title}],
            ignore_delete=True,
        )
        with self.assertRaisesRegex(workflows.WorkflowError, "remains after deletion"):
            workflows.reconcile_workflows(None, "workspace", api.request)

    def test_firewall_workflow_calls_registry_action_directly(self):
        definition = workflows.load_definition(workflows.WORKFLOW_SPECS[0])["definition"]
        actions = definition["actions"]
        self.assertEqual(
            actions[0]["action"],
            "security.supplier_intake.apply_reviewed_policy",
        )
        self.assertFalse(any(action["action"] in {"core.http_request", "core.http_poll"} for action in actions))
        self.assertEqual(definition["returns"], "${{ ACTIONS.apply_reviewed_rule.result }}")
        expects = definition["entrypoint"]["expects"]
        for field in ("case_id", "scenario", "proposal_revision", "mode"):
            self.assertNotIn("default", expects[field])

    def test_exact_previous_definition_is_migrated_once(self):
        api = WorkflowAPI()
        spec = workflows.WORKFLOW_SPECS[0]
        legacy = workflows.load_legacy_definition(spec)
        workflow_id = legacy["workflow_id"]
        api.rows[0]["title"] = legacy["definition"]["title"]
        api.definitions[workflow_id] = workflows._persisted_definition(legacy["definition"])

        def upload(_client, _workspace_id, actual_spec, document):
            replacement = {
                "id": workflow_id,
                "title": document["definition"]["title"],
                "alias": actual_spec.alias,
                "version": 1,
                "status": "online",
            }
            api.rows.append(copy.deepcopy(replacement))
            api.definitions[workflow_id] = workflows._persisted_definition(document["definition"])
            api._set_graph(workflow_id, positioned=True)
            return replacement

        with patch.object(workflows, "_upload", side_effect=upload) as mocked:
            workflows.reconcile_workflows(None, "workspace", api.request)
            workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertEqual(mocked.call_count, 1)

    def test_unknown_workflow_drift_is_rejected(self):
        api = WorkflowAPI()
        workflow_id = api.rows[0]["id"]
        api.definitions[workflow_id]["description"] = "user edit"
        with self.assertRaisesRegex(workflows.WorkflowError, "has drifted"):
            workflows.reconcile_workflows(None, "workspace", api.request)

    def test_layout_is_reconciled_and_status_is_read_only(self):
        api = WorkflowAPI()
        workflow_id = api.rows[0]["id"]
        document = workflows.load_definition(workflows.WORKFLOW_SPECS[0])
        workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertTrue(
            workflows._layout_matches(
                document,
                {**api.rows[0], **api.graph[workflow_id]},
            )
        )
        snapshot = copy.deepcopy(api.graph)
        workflows.verify_workflows(None, "workspace", api.request)
        self.assertEqual(api.graph, snapshot)

    def test_analyst_uses_direct_actions_and_cannot_mutate_firewall(self):
        agent_dir = GYM_ROOT / "benchmark/agent"
        analyst = json.loads((agent_dir / "analyst-preset.json").read_text())
        actions = set(analyst["actions"])
        self.assertTrue(
            {
                "security.supplier_intake.scan",
                "security.supplier_intake.verify",
                "security.supplier_intake.propose_policy",
            }
            <= actions
        )
        self.assertNotIn("core.workflow.execute", actions)
        self.assertNotIn("security.supplier_intake.apply_reviewed_policy", actions)
        self.assertEqual(set(analyst["tool_approvals"]), actions)
        self.assertTrue(all(value is False for value in analyst["tool_approvals"].values()))
        prompt = (agent_dir / analyst["prompt_file"]).read_text()
        self.assertIn("Never execute a workflow", prompt)
        self.assertIn("underlying application remains vulnerable", prompt)

    def test_two_human_tasks_use_only_firewall_workflow(self):
        definitions = reconcile._task_definitions(
            "case-id", {"gym-003-rule-application": {"id": "workflow-id"}}
        )
        self.assertEqual({row["title"] for row in definitions}, {"Create BLOCK rule", "Create LOG-only rule"})
        self.assertTrue(all(row["workflow_id"] == "workflow-id" for row in definitions))


if __name__ == "__main__":
    unittest.main()
