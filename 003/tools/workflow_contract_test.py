#!/usr/bin/env python3
"""Offline contracts for the Tracecat-native Agent and firewall workflow."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

GYM_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(GYM_ROOT / "src"), str(GYM_ROOT.parent / "src")]

from gym_plugin import reconcile, workflows  # noqa: E402


def reviewable_proposal():
    proposal = {
        "scenario": reconcile.SCENARIO,
        "revision": 1,
        "route": "/form/supplier-intake",
        "method": "POST",
        "allowed_content_type": "multipart/form-data",
        "recommended_mode": "BLOCK",
        "rationale": "Confirmed impact justifies a narrow ingress control.",
        "created_at": "2026-09-07T00:00:00+00:00",
    }
    signed = {key: proposal[key] for key in reconcile.PROPOSAL_DIGEST_FIELDS}
    canonical = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    proposal["proposal_id"] = hashlib.sha256(canonical).hexdigest()
    return proposal


class WorkflowAPI:
    def __init__(self, extra=(), *, ignore_delete=False):
        self.rows: list[dict] = []
        self.definitions: dict[str, dict] = {}
        self.webhooks: dict[str, dict] = {}
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
            self.webhooks[row["id"]] = {
                "secret": f"secret-{row['id']}",
                "status": "offline",
                "methods": ["POST"],
                "entrypoint_ref": None,
                "allowlisted_cidrs": [],
                "include_headers": False,
            }
            self._set_graph(row["id"], positioned=False)
        self.rows.extend(copy.deepcopy(extra))

    def _set_graph(self, workflow_id, *, positioned):
        self.graph = getattr(self, "graph", {})
        spec = next(
            spec
            for spec in workflows.WORKFLOW_SPECS
            if workflows.load_definition(spec)["workflow_id"] == workflow_id
        )
        document = workflows.load_definition(spec)
        self.graph[workflow_id] = {
            "actions": {
                f"action-{index}": {
                    "id": f"action-{index}",
                    "ref": item["ref"],
                    "position_x": float(item["x"]) if positioned else 0.0,
                    "position_y": float(item["y"]) if positioned else 0.0,
                }
                for index, item in enumerate(document["layout"]["actions"])
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
        if tail.endswith("/webhook"):
            workflow_id = tail.removesuffix("/webhook")
            if method == "GET":
                return copy.deepcopy(self.webhooks[workflow_id])
            if method == "PATCH":
                self.webhooks[workflow_id].update(copy.deepcopy(kwargs["body"]))
                return None
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


class IntakeWebhookClient:
    def __init__(self, state, *, status_code=200, create_proposal=True):
        self.state = state
        self.status_code = status_code
        self.create_proposal = create_proposal
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if self.status_code == 200 and self.create_proposal:
            self.state["payload"]["firewall_proposal"] = reviewable_proposal()
        return type("Response", (), {"status_code": self.status_code})()


def case_request(state, patches):
    def request(_client, method, url, **kwargs):
        if method == "GET":
            return {"id": "case-id", "payload": copy.deepcopy(state["payload"])}
        if method == "PATCH":
            payload = copy.deepcopy(kwargs["body"]["payload"])
            state["payload"] = payload
            patches.append(payload)
            return None
        raise AssertionError(f"unexpected request: {method} {url}")

    return request


class WorkflowContractTests(unittest.TestCase):
    def test_only_exact_immutable_proposal_marks_analyst_complete(self):
        proposal = reviewable_proposal()
        self.assertTrue(reconcile._is_reviewable_firewall_proposal(proposal))
        self.assertFalse(
            reconcile._is_reviewable_firewall_proposal({"proposal_id": "proposal"})
        )
        tampered = {**proposal, "route": "/admin"}
        self.assertFalse(reconcile._is_reviewable_firewall_proposal(tampered))

    def test_reconcile_builds_human_review_path_before_initial_dispatch(self):
        calls = []
        client = object()
        managed = {
            "gym-003-scanner-intake": {"id": "intake"},
            "gym-003-rule-application": {"id": "firewall"},
        }
        with (
            patch.object(reconcile.tracecat, "client", return_value=nullcontext(client)),
            patch.object(reconcile, "request", return_value=None),
            patch.object(reconcile.tracecat, "login", return_value="workspace"),
            patch.object(reconcile.tracecat, "verify_entitlements"),
            patch.object(
                reconcile,
                "reconcile_registry",
                side_effect=lambda *_: calls.append("registry"),
            ),
            patch.object(
                reconcile,
                "reconcile_action_secrets",
                side_effect=lambda *_: calls.append("secrets"),
            ),
            patch.object(
                reconcile,
                "reconcile_case",
                side_effect=lambda *_: calls.append("case") or {"id": "case-id"},
            ),
            patch.object(
                reconcile,
                "retire_legacy_case_artifacts",
                side_effect=lambda *_: calls.append("legacy"),
            ),
            patch.object(
                reconcile,
                "reconcile_skills",
                side_effect=lambda *_: calls.append("skills") or ["skill-id"],
            ),
            patch.object(
                reconcile,
                "reconcile_presets",
                side_effect=lambda *_: calls.append("preset"),
            ),
            patch.object(
                workflows,
                "reconcile_workflows",
                side_effect=lambda *_args, **_kwargs: calls.append("workflows")
                or managed,
            ),
            patch.object(
                reconcile,
                "reconcile_tasks",
                side_effect=lambda *_: calls.append("tasks"),
            ),
            patch.object(
                reconcile,
                "reconcile_initial_analyst_dispatch",
                side_effect=lambda *_: calls.append("dispatch"),
            ),
        ):
            reconcile.reconcile()

        self.assertEqual(
            calls,
            [
                "registry",
                "secrets",
                "case",
                "legacy",
                "skills",
                "preset",
                "workflows",
                "tasks",
                "dispatch",
            ],
        )

    def test_one_automatic_and_one_human_workflow_and_three_retired_wrappers(self):
        self.assertEqual(
            [spec.filename for spec in workflows.WORKFLOW_SPECS],
            ["scanner-intake.json", "rule-application.json"],
        )
        self.assertEqual(
            [spec.alias for spec in workflows.WORKFLOW_SPECS],
            ["scanner-intake", None],
        )
        self.assertEqual(len(workflows.RETIRED_WORKFLOWS), 3)
        api = WorkflowAPI(
            [
                {"id": stable_id, "alias": alias, "title": title}
                for stable_id, alias, title in workflows.RETIRED_WORKFLOWS
            ]
        )
        actual = workflows.reconcile_workflows(None, "workspace", api.request)
        self.assertEqual(
            set(actual),
            {"gym-003-scanner-intake", "gym-003-rule-application"},
        )
        self.assertEqual(len(api.rows), 2)
        self.assertEqual(len(api.deletions), 3)
        intake_id = workflows.load_definition(workflows.WORKFLOW_SPECS[0])["workflow_id"]
        self.assertEqual(
            api.webhooks[intake_id],
            {
                "secret": f"secret-{intake_id}",
                "status": "online",
                "methods": ["POST"],
                "entrypoint_ref": None,
                "allowlisted_cidrs": [],
                "include_headers": False,
            },
        )
        self.assertEqual(
            len(workflows.verify_workflows(None, "workspace", api.request)), 2
        )

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
        spec = next(
            spec
            for spec in workflows.WORKFLOW_SPECS
            if spec.key == "gym-003-rule-application"
        )
        definition = workflows.load_definition(spec)["definition"]
        actions = definition["actions"]
        self.assertEqual(definition["config"]["timeout"], 480)
        self.assertEqual(
            actions[0]["action"],
            "security.supplier_intake.apply_reviewed_policy",
        )
        self.assertFalse(any(action["action"] in {"core.http_request", "core.http_poll"} for action in actions))
        self.assertEqual(definition["returns"], "${{ ACTIONS.apply_reviewed_rule.result }}")
        comment = actions[1]["args"]["content"]
        self.assertIn("result.rollback.attempted", comment)
        self.assertIn("result.rollback.succeeded", comment)
        self.assertIn("Malice | Pre-change verdict:", comment)
        self.assertNotIn("Malice | Confirmed against the tested ingress", comment)
        expects = definition["entrypoint"]["expects"]
        for field in ("case_id", "scenario", "proposal_revision", "mode"):
            self.assertNotIn("default", expects[field])

        review = actions[2]
        self.assertEqual(review["action"], "ai.preset_agent")
        self.assertEqual(review["depends_on"], ["record_rule_result"])
        self.assertEqual(review["args"]["preset"], "analyst")
        self.assertIn("post the closure assessment", review["args"]["user_prompt"])

    def test_scanner_intake_runs_analyst_without_firewall_authority(self):
        spec = next(
            spec
            for spec in workflows.WORKFLOW_SPECS
            if spec.key == "gym-003-scanner-intake"
        )
        definition = workflows.load_definition(spec)["definition"]
        self.assertEqual(definition["config"]["timeout"], 480)
        self.assertEqual(definition["entrypoint"]["ref"], "run_analyst")
        self.assertEqual(len(definition["actions"]), 1)
        action = definition["actions"][0]
        self.assertEqual(action["action"], "ai.preset_agent")
        self.assertEqual(action["args"]["preset"], "analyst")
        self.assertIn("${{ TRIGGER.case_id }}", action["args"]["user_prompt"])
        self.assertIn(
            "without waiting for human confirmation", action["args"]["user_prompt"]
        )
        self.assertIn("human reviews the case", action["args"]["user_prompt"])
        self.assertNotIn(
            "security.supplier_intake.apply_reviewed_policy", json.dumps(action)
        )

    def test_initial_finding_dispatch_uses_webhook_once_and_reaches_review(self):
        state = {"payload": {"scanner_assessment": "suspected_vulnerable_version"}}
        patches = []
        client = IntakeWebhookClient(state)
        workflow = {
            "id": "workflow-id",
            "webhook": {"status": "online", "secret": "never-persist-this"},
        }
        with patch.object(reconcile, "request", side_effect=case_request(state, patches)):
            self.assertTrue(
                reconcile.reconcile_initial_analyst_dispatch(
                    client, "workspace", "case-id", workflow
                )
            )
            self.assertFalse(
                reconcile.reconcile_initial_analyst_dispatch(
                    client, "workspace", "case-id", workflow
                )
            )

        self.assertEqual(len(client.calls), 1)
        method, url, kwargs = client.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "/webhooks/workflow-id/never-persist-this/wait")
        self.assertEqual(
            kwargs["json"],
            {
                "case_id": "case-id",
                "source": "webhook",
                "scanner_assessment": "suspected_vulnerable_version",
            },
        )
        self.assertEqual(state["payload"][reconcile.ANALYST_DISPATCH_KEY]["status"], "complete")
        self.assertNotIn("never-persist-this", json.dumps(patches))

    def test_existing_proposal_converges_marker_without_dispatch(self):
        state = {"payload": {"firewall_proposal": reviewable_proposal()}}
        patches = []
        client = IntakeWebhookClient(state)
        workflow = {"id": "workflow-id"}
        with patch.object(reconcile, "request", side_effect=case_request(state, patches)):
            self.assertFalse(
                reconcile.reconcile_initial_analyst_dispatch(
                    client, "workspace", "case-id", workflow
                )
            )
            self.assertFalse(
                reconcile.reconcile_initial_analyst_dispatch(
                    client, "workspace", "case-id", workflow
                )
            )
        self.assertEqual(client.calls, [])
        self.assertEqual(len(patches), 1)
        self.assertEqual(
            state["payload"][reconcile.ANALYST_DISPATCH_KEY],
            {"status": "complete", "source": "webhook", "workflow_id": "workflow-id"},
        )

    def test_requested_dispatch_without_proposal_refuses_duplicate(self):
        state = {
            "payload": {
                reconcile.ANALYST_DISPATCH_KEY: {
                    "status": "requested",
                    "source": "webhook",
                    "workflow_id": "workflow-id",
                }
            }
        }
        patches = []
        client = IntakeWebhookClient(state)
        with patch.object(reconcile, "request", side_effect=case_request(state, patches)):
            with self.assertRaisesRegex(reconcile.ReconcileError, "refusing to launch"):
                reconcile.reconcile_initial_analyst_dispatch(
                    client,
                    "workspace",
                    "case-id",
                    {
                        "id": "workflow-id",
                        "webhook": {"status": "online", "secret": "secret"},
                    },
                )
        self.assertEqual(client.calls, [])
        self.assertEqual(patches, [])

    def test_webhook_rejection_allows_a_safe_retry(self):
        state = {"payload": {}}
        patches = []
        client = IntakeWebhookClient(state, status_code=422, create_proposal=False)
        workflow = {
            "id": "workflow-id",
            "webhook": {"status": "online", "secret": "never-persist-this"},
        }
        with patch.object(reconcile, "request", side_effect=case_request(state, patches)):
            with self.assertRaisesRegex(reconcile.ReconcileError, "HTTP 422"):
                reconcile.reconcile_initial_analyst_dispatch(
                    client, "workspace", "case-id", workflow
                )
        self.assertEqual(
            state["payload"][reconcile.ANALYST_DISPATCH_KEY]["status"],
            "failed_before_start",
        )
        self.assertNotIn("never-persist-this", json.dumps(patches))

    def test_webhook_transport_failure_redacts_secret_and_blocks_duplicate(self):
        state = {"payload": {}}
        patches = []

        class FailingClient:
            def request(self, _method, url, **_kwargs):
                raise RuntimeError(url)

        workflow = {
            "id": "workflow-id",
            "webhook": {"status": "online", "secret": "never-report-this"},
        }
        with patch.object(reconcile, "request", side_effect=case_request(state, patches)):
            with self.assertRaises(reconcile.ReconcileError) as raised:
                reconcile.reconcile_initial_analyst_dispatch(
                    FailingClient(), "workspace", "case-id", workflow
                )
        self.assertNotIn("never-report-this", str(raised.exception))
        self.assertEqual(
            state["payload"][reconcile.ANALYST_DISPATCH_KEY]["status"], "requested"
        )

    def test_exact_previous_definition_is_migrated_once(self):
        api = WorkflowAPI()
        spec = next(
            spec
            for spec in workflows.WORKFLOW_SPECS
            if spec.key == "gym-003-rule-application"
        )
        legacy = next(
            candidate
            for candidate in workflows.load_legacy_definitions(spec)
            if candidate["definition"]["actions"][0]["action"]
            == "security.supplier_intake.apply_reviewed_policy"
        )
        workflow_id = legacy["workflow_id"]
        row = next(row for row in api.rows if row["id"] == workflow_id)
        row["title"] = legacy["definition"]["title"]
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
        workflows.reconcile_workflows(None, "workspace", api.request)
        for spec in workflows.WORKFLOW_SPECS:
            document = workflows.load_definition(spec)
            workflow_id = document["workflow_id"]
            row = next(row for row in api.rows if row["id"] == workflow_id)
            self.assertTrue(
                workflows._layout_matches(
                    document,
                    {**row, **api.graph[workflow_id]},
                )
            )
        snapshot = copy.deepcopy(api.graph)
        workflows.verify_workflows(None, "workspace", api.request)
        self.assertEqual(api.graph, snapshot)

    def test_status_rejects_offline_scanner_webhook_without_mutation(self):
        api = WorkflowAPI()
        workflows.reconcile_workflows(None, "workspace", api.request)
        intake_id = workflows.load_definition(workflows.WORKFLOW_SPECS[0])[
            "workflow_id"
        ]
        api.webhooks[intake_id]["status"] = "offline"
        snapshot = copy.deepcopy(api.webhooks)

        with self.assertRaisesRegex(workflows.WorkflowError, "not online"):
            workflows.verify_workflows(None, "workspace", api.request)

        self.assertEqual(api.webhooks, snapshot)

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
