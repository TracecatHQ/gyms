"""Load and validate Gym 002's private evaluation contracts."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, TypedDict, cast

from gymctl import agents
from gymctl.evidence import EVENT_REF_VERSION

from . import reconcile


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2]))
AGENT_DIR = ROOT / "benchmark/agent"
EVALS_DIR = ROOT / "benchmark/evals"
RESULTS_ROOT = Path(os.environ.get("GYM_EVAL_RESULTS_DIR", "/opt/gym/eval-results"))
REF_RE = re.compile(r"\b[0-9a-f]{64}\b")
BASE_GATE_KEYS = (
    "determination",
    "incident_relevance",
    "exact_object",
    "case_evidence",
    "evidence_support",
)
SEMANTIC_GATE_KEY = "evidence_support"


class EvalError(RuntimeError):
    pass


class CaseContract(TypedDict):
    alert_id: str
    expected_determination: str
    expected_incident_relevance: str
    basis: str
    event_object_key: str
    anchor_event_refs: list[str]
    required_enrichments: list[str]
    enrichment_targets: list[str]
    validation_gates: list[str]
    canonical_case: dict[str, Any]


class ManagedCase(TypedDict):
    id: str
    snapshot: dict[str, Any]
    case: dict[str, Any]


def load_configuration() -> dict[str, Any]:
    path = EVALS_DIR / "evaluation.json"
    try:
        config = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvalError(f"cannot load evaluation configuration: {exc}") from exc
    expected_keys = {
        "schema_version",
        "classification",
        "investigator_timeout_seconds",
        "judge_timeout_seconds",
        "max_attempts",
        "investigation_prompt_file",
        "investigator_preset_slug",
        "investigator_workflow",
        "judge",
        "validation_gates",
        "enrichment_validation_gates",
    }
    if not isinstance(config, dict) or set(config) != expected_keys:
        raise EvalError("evaluation configuration has an invalid shape")
    if config["schema_version"] != 2 or config["classification"] != "gym-owned":
        raise EvalError("evaluation configuration identity drifted")
    for key in ("investigator_timeout_seconds", "judge_timeout_seconds"):
        if (
            not isinstance(config[key], int)
            or isinstance(config[key], bool)
            or config[key] <= 0
        ):
            raise EvalError(f"{key} must be a positive integer")
    if config["max_attempts"] != 3:
        raise EvalError("max_attempts must be exactly 3")
    prompt_path = (EVALS_DIR / str(config["investigation_prompt_file"])).resolve()
    if prompt_path.parent != AGENT_DIR.resolve():
        raise EvalError("investigation prompt must resolve inside benchmark/agent")
    config["investigation_prompt"] = prompt_path.read_text().strip()
    if not config["investigation_prompt"]:
        raise EvalError("investigation prompt is empty")
    if not isinstance(config["investigator_preset_slug"], str):
        raise EvalError("investigator preset slug is missing")
    workflow = config["investigator_workflow"]
    if (
        not isinstance(workflow, dict)
        or set(workflow) != {"alias"}
        or not isinstance(workflow["alias"], str)
        or not workflow["alias"]
    ):
        raise EvalError("investigator workflow configuration drifted")
    if config["judge"] != {
        "model_provider": "openai",
        "model_name": "gpt-5.6-sol",
        "preset_slug": "gym-002-evaluation-grader",
    }:
        raise EvalError("grader configuration drifted")
    gates = config["validation_gates"]
    if (
        not isinstance(gates, dict)
        or tuple(gates) != BASE_GATE_KEYS
        or not all(isinstance(value, str) and value for value in gates.values())
        or len(set(gates.values())) != len(gates)
    ):
        raise EvalError("base validation gates drifted")
    enrichment_gates = config["enrichment_validation_gates"]
    if (
        not isinstance(enrichment_gates, dict)
        or tuple(enrichment_gates) != ("urlscan", "virustotal")
        or not all(
            isinstance(value, str) and value for value in enrichment_gates.values()
        )
    ):
        raise EvalError("enrichment validation gates drifted")
    return config


def load_contracts(config: dict[str, Any]) -> list[CaseContract]:
    try:
        payload = json.loads((EVALS_DIR / "cases.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvalError(f"cannot load evaluation cases: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema_version",
            "event_ref_version",
            "determination_values",
            "incident_relevance_values",
            "cases",
        }
        or payload["schema_version"] != 2
        or payload["event_ref_version"] != EVENT_REF_VERSION
        or payload["determination_values"] != ["true_positive", "false_positive"]
        or payload["incident_relevance_values"] != ["related", "unrelated"]
        or not isinstance(payload["cases"], list)
    ):
        raise EvalError("evaluation case file has an invalid shape")
    canonical = {
        str(row["payload"]["alert_id"]): row for row in reconcile.source_cases()
    }
    contracts: list[CaseContract] = []
    expected_case_keys = {
        "alert_id",
        "expected_determination",
        "expected_incident_relevance",
        "basis",
        "event_object_key",
        "anchor_event_refs",
        "required_enrichments",
        "enrichment_targets",
    }
    seen: set[str] = set()
    for row in payload["cases"]:
        if not isinstance(row, dict) or set(row) != expected_case_keys:
            raise EvalError("an evaluation case has an invalid shape")
        alert_id = str(row["alert_id"])
        source = canonical.get(alert_id)
        if source is None or alert_id in seen:
            raise EvalError(f"unknown or duplicate evaluation case: {alert_id}")
        seen.add(alert_id)
        if row["expected_determination"] not in {
            "true_positive",
            "false_positive",
        }:
            raise EvalError(f"invalid determination for {alert_id}")
        if row["expected_incident_relevance"] not in {"related", "unrelated"}:
            raise EvalError(f"invalid incident relevance for {alert_id}")
        if (
            not isinstance(row["basis"], str)
            or not row["basis"]
            or not isinstance(row["anchor_event_refs"], list)
            or not row["anchor_event_refs"]
            or not all(REF_RE.fullmatch(ref) for ref in row["anchor_event_refs"])
        ):
            raise EvalError(f"invalid evidence contract for {alert_id}")
        required = row["required_enrichments"]
        if required not in ([], ["urlscan", "virustotal"]):
            raise EvalError(f"invalid enrichment requirements for {alert_id}")
        targets = row["enrichment_targets"]
        if (
            not isinstance(targets, list)
            or len(targets) != (1 if required else 0)
            or not all(
                isinstance(target, str) and target and target == target.strip()
                for target in targets
            )
        ):
            raise EvalError(f"invalid enrichment targets for {alert_id}")
        payload_key = source["payload"].get("event_object_key")
        payload_url = source["payload"].get("event_object_url")
        if (
            row["event_object_key"] != payload_key
            or not isinstance(payload_url, str)
            or payload_url.rsplit("/", 1)[-1] != row["event_object_key"]
        ):
            raise EvalError(f"object contract disagrees with scenario for {alert_id}")
        gates = [config["validation_gates"][key] for key in BASE_GATE_KEYS]
        gates.extend(config["enrichment_validation_gates"][name] for name in required)
        contracts.append(
            cast(
                CaseContract,
                {
                    **row,
                    "validation_gates": gates,
                    "canonical_case": source,
                },
            )
        )
    if len(contracts) != 20 or seen != set(canonical):
        raise EvalError("evaluation contracts must exactly map the 20-case queue")
    return contracts


def preflight_cases(
    api: agents.TracecatAPI,
    workspace_id: str,
    contracts: list[CaseContract],
) -> dict[str, ManagedCase]:
    managed = reconcile.list_managed_cases(api.client, workspace_id)
    selected: dict[str, ManagedCase] = {}
    problems: list[str] = []
    for contract in contracts:
        alert_id = contract["alert_id"]
        case = managed.get(alert_id)
        if case is None:
            problems.append(f"{alert_id}: managed case is missing")
            continue
        case_id = str(case["id"])
        snapshot = agents.case_snapshot(api, workspace_id, case_id)
        actual = snapshot["case"]
        desired = contract["canonical_case"]
        drift = [
            key for key in reconcile.STATIC_CASE_KEYS if actual.get(key) != desired[key]
        ]
        sessions = reconcile.case_sessions(api.client, workspace_id, case_id)
        if drift:
            problems.append(f"{alert_id}: case fields drifted ({', '.join(drift)})")
        if actual.get("tags"):
            problems.append(f"{alert_id}: case already has tags")
        if snapshot["comments"]:
            problems.append(f"{alert_id}: case already has comments")
        if sessions:
            problems.append(f"{alert_id}: case already has an investigation session")
        selected[alert_id] = {"id": case_id, "snapshot": snapshot, "case": actual}
    if problems:
        raise EvalError(
            "selected cases are not clean; preserve artifacts, then run `just "
            "reset-evals CONFIRM=artifacts-captured`:\n  - " + "\n  - ".join(problems)
        )
    return selected
