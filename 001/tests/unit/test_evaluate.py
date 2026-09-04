from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gymctl import evaluate as eval_runner

ROOT = Path(__file__).parents[2]


def manifest() -> dict[str, Any]:
    return eval_runner.load_manifest(ROOT / "benchmark" / "scorecard.json")


def judgment(
    *,
    disposition: str = "true_positive",
    verdict: str = "met",
    incorrect_claims: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    case = manifest()
    return {
        "disposition": disposition,
        "disposition_evidence": "This is a true positive.",
        "gates": [
            {
                "id": gate["id"],
                "verdict": verdict,
                "evidence": "Supported finding.",
                "reason": "The report states the required finding.",
            }
            for gate in case["validation_gates"]
        ],
        "incorrect_claims": incorrect_claims or [],
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


def test_manifest_checksum_and_weights_are_locked() -> None:
    case = manifest()
    scorecard = json.loads((ROOT / "benchmark" / "scorecard.json").read_text())
    assert scorecard["manifest_sha256"] == eval_runner.canonical_manifest_hash(scorecard)
    assert sum(gate["weight"] for gate in case["validation_gates"]) == 100
    assert len(case["validation_gates"]) == 16


def test_all_met_scores_one_hundred() -> None:
    score = eval_runner.score_judgment(judgment(), manifest())
    assert score["public_score"] == 100
    assert score["quality_status"] == "pass"


def test_ambiguous_gates_earn_no_points() -> None:
    score = eval_runner.score_judgment(
        judgment(verdict="ambiguous"), manifest()
    )
    assert score["public_score"] == 0
    assert score["disposition_hard_fail"] is False


def test_wrong_disposition_hard_fails_an_otherwise_complete_report() -> None:
    score = eval_runner.score_judgment(
        judgment(disposition="false_positive"), manifest()
    )
    assert score["recall_score_before_hard_gate"] == 100
    assert score["public_score"] == 0
    assert score["disposition_hard_fail"] is True
    assert score["quality_status"] == "fail"


def test_critical_false_claim_fails_quality_without_changing_public_score() -> None:
    score = eval_runner.score_judgment(
        judgment(
            incorrect_claims=[
                {
                    "claim": "The legitimate operator was the attacker.",
                    "severity": "critical",
                    "reason": "This contradicts the reference facts.",
                }
            ]
        ),
        manifest(),
    )
    assert score["public_score"] == 100
    assert score["quality_status"] == "fail"
    assert score["critical_incorrect_claims"] == 1


def test_median_aggregation_reports_public_comparison_metrics() -> None:
    runs = [
        {
            "score": {
                "public_score": value,
                "disposition_hard_fail": value == 0,
                "quality_status": "fail" if value == 0 else "pass",
            }
        }
        for value in (20, 80, 50)
    ]
    aggregate = eval_runner.aggregate_scores(runs)
    assert aggregate["headline_score"] == 50
    assert aggregate["mean_score"] == 50
    assert aggregate["best_score"] == 80
    assert aggregate["best_of_first_two"] == 80
    assert aggregate["hard_failure_count"] == 0


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
    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.created_investigators: list[str] = []
        self.created_graders: list[str] = []
        self.deleted: list[str] = []

    def login(self, email: str, password: str) -> str:
        assert email and password
        return "workspace-1"

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        if method == "GET" and path.endswith("/agent/presets"):
            return [
                {"id": "investigator", "slug": self.case["investigator_preset_slug"]},
                {"id": "grader", "slug": self.case["judge"]["preset_slug"]},
            ]
        if method == "GET" and path.endswith("/agent/presets/investigator"):
            return {
                "id": "investigator",
                "slug": self.case["investigator_preset_slug"],
                "current_version_id": "investigator-version",
                "model_provider": "openai",
                "model_name": "gpt-5.6-terra",
                "actions": [],
                "mcp_integrations": ["splunk"],
            }
        if method == "GET" and path.endswith("/agent/presets/grader"):
            return {
                "id": "grader",
                "slug": self.case["judge"]["preset_slug"],
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
            else:
                session_id = f"grader-{len(self.created_graders) + 1}"
                self.created_graders.append(session_id)
            return {"id": session_id}
        if method == "GET" and path.endswith("/vercel"):
            session_id = path.split("/")[-2]
            if session_id.startswith("investigator-"):
                return assistant_session("True positive. Complete investigation report.")
            return assistant_session(json.dumps(judgment()))
        if method == "DELETE" and "/agent/sessions/" in path:
            self.deleted.append(path.rsplit("/", 1)[-1])
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    def stream_message(self, *args: Any, **kwargs: Any) -> None:
        return None


def test_mocked_three_run_flow_keeps_investigators_and_deletes_graders(
    tmp_path: Path, monkeypatch: Any
) -> None:
    case = manifest()
    fake = FakeAPI(case)
    monkeypatch.setenv("TRACEcat_TENANT_EMAIL", "analyst@example.com")
    monkeypatch.setenv("TRACEcat_TENANT_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("TRACEcat_PUBLIC_APP_URL", "http://127.0.0.1:18080")
    result = eval_runner.run_evaluation(fake, case, tmp_path, 3)
    assert len(set(fake.created_investigators)) == 3
    assert len(fake.created_graders) == 3
    assert fake.deleted == fake.created_graders
    assert not (set(fake.created_investigators) & set(fake.deleted))
    assert result["aggregate"]["headline_score"] == 100
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "report.md").exists()


class TimedOutInvestigatorAPI(FakeAPI):
    def stream_message(self, *args: Any, **kwargs: Any) -> None:
        raise TimeoutError("mock investigator timeout")

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
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
        return super().request_json(
            method, path, body=body, expected=expected
        )


def test_investigator_timeout_preserves_failed_state_and_tool_calls(
    tmp_path: Path, monkeypatch: Any
) -> None:
    case = manifest()
    fake = TimedOutInvestigatorAPI(case)
    monkeypatch.setenv("TRACEcat_TENANT_EMAIL", "analyst@example.com")
    monkeypatch.setenv("TRACEcat_TENANT_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("TRACEcat_PUBLIC_APP_URL", "http://127.0.0.1:18080")
    try:
        eval_runner.run_evaluation(fake, case, tmp_path, 1)
    except TimeoutError as exc:
        assert str(exc) == "mock investigator timeout"
    else:
        raise AssertionError("expected mocked investigator timeout")
    state = json.loads((tmp_path / "run-01" / "state.json").read_text())
    calls = json.loads((tmp_path / "run-01" / "tool-calls.json").read_text())
    assert state["status"] == "failed"
    assert state["error_type"] == "TimeoutError"
    assert calls[0]["input"]["query"] == "index=investigation | stats count"
    assert fake.deleted == []


class FakeGradingAPI:
    def __init__(self, responses: list[str], stream_error: Exception | None = None) -> None:
        self.responses = responses
        self.stream_error = stream_error
        self.stream_count = 0
        self.deleted: list[str] = []

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        if method == "POST" and path.endswith("/agent/sessions"):
            return {"id": "grader-session"}
        if method == "GET" and path.endswith("/grader-session/vercel"):
            response_index = max(self.stream_count - 1, 0)
            return assistant_session(self.responses[response_index])
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
    case = manifest()
    api = FakeGradingAPI(["not JSON", json.dumps(judgment())])
    graded, raw = eval_runner.grade_report(
        api,
        "workspace-1",
        grader_preset(),
        case,
        "candidate report",
        "eval-1",
        1,
    )
    assert graded["disposition"] == "true_positive"
    assert raw[0] == "not JSON"
    assert len(raw) == 2
    assert api.stream_count == 2
    assert api.deleted == ["grader-session"]


def test_grader_timeout_deletes_only_the_transient_session() -> None:
    case = manifest()
    api = FakeGradingAPI([], stream_error=TimeoutError("mock timeout"))
    try:
        eval_runner.grade_report(
            api,
            "workspace-1",
            grader_preset(),
            case,
            "candidate report",
            "eval-1",
            1,
        )
    except TimeoutError as exc:
        assert str(exc) == "mock timeout"
    else:
        raise AssertionError("expected mocked timeout")
    assert api.deleted == ["grader-session"]
