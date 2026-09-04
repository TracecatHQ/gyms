from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from gymctl import evaluate as eval_runner
from gymctl.scenario import alert_case_payload, canonical_scenario_hash, load_scenario


ROOT = Path(__file__).parents[2]
EXPECTED_ALERT = {
    "context": "Detection of a security rule deletion on the events.amazonaws.com service.",
    "alert_date": "2026-08-13 14:34:40 UTC",
    "source_principal": "arn:aws:sts::733437130048:assumed-role/admin/save-logging",
    "source_ip": "13.38.84.140",
    "triggering_action": "DeleteRule",
}
EXPECTED_GATES = [
    ("hard fail Disposition is True Positive", 0),
    ("P7 Lambda 2 + 3 + 6 / Credentials exfiltration mechanism", 3),
    ("P6 Lambda 1 / Malicious VPC peering", 2),
    ("P6 Lambda 4 + 5 / SG of RDS + EKS API server opened", 2),
    ("P6 All Lambda creations come from ack-lambda-controller identity", 2),
    ("P6 All API calls come from the controller Pod (Python entrypoint)", 5),
    ("P6 orchestrator-sa / Patch of aws-auth", 5),
    ("P5 orchestrator-sa / Deployment of the rootkit + implant as DaemonSet", 5),
    ("P5 orchestrator backdoored through CI runner credentials reuse", 10),
    ("P4 Deployment of rootkit + implant as Static Pod", 10),
    ("P3 monitoring-sa / Exec in existing node-debugger through kubelet API", 8),
    ("P3 app-1 / Arbitrary file-read exploited in monitoring to get monitoring-sa token", 10),
    ("P2 app-1 backdoored through GitHub cache poisoning", 10),
    ("P1 External msan actor ran workflow in dev context", 8),
    ("IOC f7ef3c5ebf20a7d42636b3da48dc4a67[.]gr7[.]eu-west-1[.]eks[.]amazonaws[.]com", 5),
    ("IOC stg-shared-postgres[.]cxw88k8aqlw9[.]eu-west-1[.]rds[.]amazonaws[.]com", 10),
    ("IOC Attacker AWS account 226363753890", 5),
]


def scenario() -> dict[str, Any]:
    return load_scenario(ROOT / "benchmark/scenario.json")


def judgment(
    gates: list[dict[str, Any]], determination: str = "met"
) -> dict[str, Any]:
    return {
        "determinations": [
            {
                "validation_gate": gate["validation_gate"],
                "determination": determination,
            }
            for gate in gates
        ]
    }


def assistant_session(
    text: str, tool_parts: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "last_error": None,
        "messages": [
            {
                "role": "assistant",
                "parts": [*(tool_parts or []), {"type": "text", "text": text}],
            }
        ],
    }


def test_scenario_exactly_matches_audited_source_transcription() -> None:
    source = scenario()
    assert set(source) == {"alert", "validation_gates"}
    assert source["alert"] == EXPECTED_ALERT
    assert [
        (row["validation_gate"], row["weight"])
        for row in source["validation_gates"]
    ] == EXPECTED_GATES
    assert sum(row["weight"] for row in source["validation_gates"][1:]) == 100
    assert [row["weight"] for row in source["validation_gates"]].count(0) == 1
    assert canonical_scenario_hash(source) == (
        "863783fca1f1869e2ae570bcaa4724c94a3183636027e1a9731940bc2a9c5aed"
    )


def test_all_met_scores_one_hundred() -> None:
    gates = scenario()["validation_gates"]
    assert eval_runner.score_judgment(judgment(gates), gates) == {
        "score": 100,
        "hard_fail": False,
        "determinations": judgment(gates)["determinations"],
    }


def test_weighted_miss_subtracts_only_that_weight() -> None:
    gates = scenario()["validation_gates"]
    value = judgment(gates)
    value["determinations"][8]["determination"] = "missed"
    score = eval_runner.score_judgment(value, gates)
    assert score["score"] == 90
    assert score["hard_fail"] is False


def test_missed_disposition_hard_fails_an_otherwise_complete_report() -> None:
    gates = scenario()["validation_gates"]
    value = judgment(gates)
    value["determinations"][0]["determination"] = "missed"
    score = eval_runner.score_judgment(value, gates)
    assert score["score"] == 0
    assert score["hard_fail"] is True


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "unknown", "reordered", "nonbinary", "extra"]
)
def test_grader_contract_rejects_non_exact_determinations(mutation: str) -> None:
    gates = scenario()["validation_gates"]
    value = judgment(gates)
    rows = value["determinations"]
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows[-1] = deepcopy(rows[-2])
    elif mutation == "unknown":
        rows[3]["validation_gate"] = "invented gate"
    elif mutation == "reordered":
        rows[1], rows[2] = rows[2], rows[1]
    elif mutation == "nonbinary":
        rows[1]["determination"] = "ambiguous"
    else:
        rows[1]["reason"] = "extra evaluator field"
    with pytest.raises(eval_runner.EvalError):
        eval_runner.validate_judgment(value, gates)


def test_tool_call_artifact_redacts_credentials_but_keeps_spl() -> None:
    session = assistant_session(
        "Final report",
        [
            {
                "type": "dynamic-tool",
                "toolName": "mcp.Splunk.splunk_run_query",
                "toolCallId": "call-1",
                "state": "output-available",
                "input": {
                    "query": "index=investigation | stats count",
                    "Authorization": "Bearer secret-value",
                },
            }
        ],
    )
    report, calls = eval_runner.extract_session_artifacts(session)
    assert report == "Final report"
    assert calls[0]["input"]["query"].startswith("index=investigation")
    assert calls[0]["input"]["Authorization"] == "[REDACTED]"


class FakeAPI:
    def __init__(self, config: dict[str, Any], source: dict[str, Any]) -> None:
        self.config = config
        self.source = source
        self.created_investigators: list[str] = []
        self.created_graders: list[str] = []
        self.deleted: list[str] = []
        self.session_bodies: dict[str, dict[str, Any]] = {}
        self.messages: list[tuple[str, str]] = []
        self.case_comments: list[str] = []

    def login(self, email: str, password: str) -> str:
        assert email and password
        return "workspace-1"

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        desired_case = {
            "id": "case-1",
            "short_id": "CASE-0001",
            **alert_case_payload(self.source),
        }
        if method == "GET" and path.endswith("/cases/search"):
            assert params and params["search_term"] == EXPECTED_ALERT["context"]
            return {
                "items": [
                    {"id": "case-1", "summary": EXPECTED_ALERT["context"]}
                ]
            }
        if method == "GET" and path.endswith("/cases/case-1"):
            return desired_case
        if method == "GET" and path.endswith("/tables"):
            return [{"id": "table-1", "name": "validation_gates"}]
        if method == "GET" and path.endswith("/tables/table-1"):
            return {
                "id": "table-1",
                "name": "validation_gates",
                "columns": [
                    {
                        "name": "validation_gate",
                        "type": "TEXT",
                        "nullable": False,
                    },
                    {"name": "weight", "type": "INTEGER", "nullable": False},
                ],
            }
        if method == "GET" and path.endswith("/tables/table-1/rows"):
            assert params == {
                "limit": 100,
                "order_by": "created_at",
                "sort": "asc",
            }
            return {"items": deepcopy(self.source["validation_gates"])}
        if method == "GET" and path.endswith("/cases/case-1/rows"):
            assert params and params["table_id"] == "table-1"
            return {"items": []}
        if method == "GET" and path.endswith("/agent/presets"):
            return [
                {
                    "id": "investigator",
                    "slug": self.config["investigator_preset_slug"],
                },
                {"id": "grader", "slug": self.config["judge"]["preset_slug"]},
            ]
        if method == "GET" and path.endswith("/agent/presets/investigator"):
            return {
                "id": "investigator",
                "slug": self.config["investigator_preset_slug"],
                "current_version_id": "investigator-version",
                "model_provider": "openai",
                "model_name": "gpt-5.6-terra",
                "actions": [],
                "mcp_integrations": ["splunk"],
            }
        if method == "GET" and path.endswith("/agent/presets/grader"):
            return {
                "id": "grader",
                "slug": self.config["judge"]["preset_slug"],
                "current_version_id": "grader-version",
                "model_provider": "openai",
                "model_name": "gpt-5.6-sol",
                "actions": [],
                "mcp_integrations": [],
            }
        if method == "POST" and path.endswith("/agent/sessions"):
            if body["agent_preset_id"] == "investigator":
                session_id = f"investigator-{len(self.created_investigators) + 1}"
                self.created_investigators.append(session_id)
                stored = {
                    **body,
                    "tools": ["core.cases.get_case"],
                    "id": session_id,
                }
            else:
                session_id = f"grader-{len(self.created_graders) + 1}"
                self.created_graders.append(session_id)
                stored = {**body, "id": session_id}
            self.session_bodies[session_id] = stored
            return {"id": session_id}
        if method == "PATCH" and "/agent/sessions/" in path:
            session_id = path.rsplit("/", 1)[-1]
            self.session_bodies[session_id].update(body)
            return None
        if (
            method == "GET"
            and "/agent/sessions/" in path
            and not path.endswith("/vercel")
        ):
            return self.session_bodies[path.rsplit("/", 1)[-1]]
        if method == "GET" and path.endswith("/vercel"):
            session_id = path.split("/")[-2]
            if session_id.startswith("investigator-"):
                return assistant_session(
                    "True positive. Complete investigation report."
                )
            return assistant_session(
                json.dumps(judgment(self.source["validation_gates"]))
            )
        if method == "DELETE" and "/agent/sessions/" in path:
            self.deleted.append(path.rsplit("/", 1)[-1])
            return None
        if method == "POST" and path.endswith("/cases/case-1/comments"):
            self.case_comments.append(str(body["content"]))
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    def stream_message(
        self, workspace_id: str, session_id: str, **kwargs: Any
    ) -> None:
        assert workspace_id == "workspace-1"
        self.messages.append((session_id, str(kwargs["message"])))


def evaluation_config() -> dict[str, Any]:
    return eval_runner.load_configuration()


def set_eval_env(monkeypatch: Any) -> None:
    monkeypatch.setenv("TRACEcat_TENANT_EMAIL", "analyst@example.com")
    monkeypatch.setenv("TRACEcat_TENANT_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("TRACEcat_PUBLIC_APP_URL", "http://127.0.0.1:18080")


def test_mocked_runs_are_case_scoped_independent_and_gate_is_grader_only(
    tmp_path: Path, monkeypatch: Any
) -> None:
    source = scenario()
    config = evaluation_config()
    fake = FakeAPI(config, source)
    set_eval_env(monkeypatch)
    result = eval_runner.run_evaluation(fake, config, source, tmp_path, 2)

    assert len(set(fake.created_investigators)) == 2
    assert len(fake.created_graders) == 2
    assert fake.deleted == fake.created_graders
    assert fake.case_comments == [
        "True positive. Complete investigation report.",
        "True positive. Complete investigation report.",
    ]
    assert "aggregate" not in result
    assert len(result["runs"]) == 2
    for session_id in fake.created_investigators:
        body = fake.session_bodies[session_id]
        assert body["entity_type"] == "case"
        assert body["entity_id"] == "case-1"
        assert body["tools"] == []
        assert body["mcp_integrations"] == ["splunk"]
    investigator_messages = [
        message
        for session_id, message in fake.messages
        if session_id.startswith("investigator-")
    ]
    grader_messages = [
        message
        for session_id, message in fake.messages
        if session_id.startswith("grader-")
    ]
    assert investigator_messages == ["Is this alert a false positive?"] * 2
    assert all("validation_gates" not in message for message in investigator_messages)
    assert all(EXPECTED_GATES[1][0] in message for message in grader_messages)
    assert result["runs"][0]["session_url"] == (
        "http://127.0.0.1:18080/workspaces/workspace-1/cases/case-1"
        "?chatId=investigator-1"
    )
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "report.md").exists()


class TimedOutInvestigatorAPI(FakeAPI):
    def stream_message(
        self, workspace_id: str, session_id: str, **kwargs: Any
    ) -> None:
        if session_id.startswith("investigator-"):
            raise TimeoutError("mock investigator timeout")
        super().stream_message(workspace_id, session_id, **kwargs)

    def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        if method == "GET" and path.endswith("/investigator-1/vercel"):
            return assistant_session(
                "",
                [
                    {
                        "type": "tool-mcp.Splunk._Gym_001.splunk_run_query",
                        "toolCallId": "call-1",
                        "state": "output-available",
                        "input": {"query": "index=investigation | stats count"},
                    }
                ],
            )
        return super().request_json(method, path, **kwargs)


def test_investigator_timeout_preserves_failed_state_and_tool_calls(
    tmp_path: Path, monkeypatch: Any
) -> None:
    source = scenario()
    config = evaluation_config()
    fake = TimedOutInvestigatorAPI(config, source)
    set_eval_env(monkeypatch)
    with pytest.raises(TimeoutError, match="mock investigator timeout"):
        eval_runner.run_evaluation(fake, config, source, tmp_path, 1)
    state = json.loads((tmp_path / "run-01/state.json").read_text())
    calls = json.loads((tmp_path / "run-01/tool-calls.json").read_text())
    assert state["status"] == "failed"
    assert state["error_type"] == "TimeoutError"
    assert calls[0]["input"]["query"] == "index=investigation | stats count"
    assert fake.deleted == []


class FakeGradingAPI:
    def __init__(
        self, responses: list[str], stream_error: Exception | None = None
    ) -> None:
        self.responses = responses
        self.stream_error = stream_error
        self.stream_count = 0
        self.deleted: list[str] = []

    def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        if method == "POST" and path.endswith("/agent/sessions"):
            return {"id": "grader-session"}
        if method == "GET" and path.endswith("/grader-session/vercel"):
            return assistant_session(self.responses[max(self.stream_count - 1, 0)])
        if method == "DELETE" and path.endswith("/grader-session"):
            self.deleted.append("grader-session")
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    def stream_message(self, *args: Any, **kwargs: Any) -> None:
        self.stream_count += 1
        if self.stream_error is not None:
            raise self.stream_error


def grader_preset() -> dict[str, Any]:
    return {
        "id": "grader",
        "current_version_id": "grader-version",
        "model_provider": "openai",
        "model_name": "gpt-5.6-sol",
        "actions": [],
        "mcp_integrations": [],
    }


def test_malformed_grader_output_gets_one_repair_attempt() -> None:
    gates = scenario()["validation_gates"]
    api = FakeGradingAPI(["not JSON", json.dumps(judgment(gates))])
    graded, raw = eval_runner.grade_report(
        api,
        "workspace-1",
        grader_preset(),
        {"judge_timeout_seconds": 300},
        gates,
        "candidate report",
        "eval-1",
        1,
    )
    assert graded == judgment(gates)
    assert raw[0] == "not JSON"
    assert len(raw) == 2
    assert api.stream_count == 2
    assert api.deleted == ["grader-session"]


def test_grader_timeout_deletes_only_the_transient_session() -> None:
    gates = scenario()["validation_gates"]
    api = FakeGradingAPI([], stream_error=TimeoutError("mock timeout"))
    with pytest.raises(TimeoutError, match="mock timeout"):
        eval_runner.grade_report(
            api,
            "workspace-1",
            grader_preset(),
            {"judge_timeout_seconds": 300},
            gates,
            "candidate report",
            "eval-1",
            1,
        )
    assert api.deleted == ["grader-session"]
