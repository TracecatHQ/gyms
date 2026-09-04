"""Source-faithful Gym 001 alert and validation-gate declaration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


GYM_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_FILE = GYM_ROOT / "benchmark/scenario.json"
HARD_FAIL_GATE = "hard fail Disposition is True Positive"
VALIDATION_GATES_TABLE = "validation_gates"
ALERT_KEYS = {
    "context",
    "alert_date",
    "source_principal",
    "source_ip",
    "triggering_action",
}


class ScenarioError(RuntimeError):
    """The Git-owned scenario declaration is malformed or has drifted."""


def canonical_scenario_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_scenario(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"alert", "validation_gates"}:
        raise ScenarioError("scenario must contain only alert and validation_gates")
    alert = value["alert"]
    if not isinstance(alert, dict) or set(alert) != ALERT_KEYS:
        raise ScenarioError(f"scenario alert must contain exactly {sorted(ALERT_KEYS)}")
    if not all(isinstance(alert[key], str) and alert[key] for key in ALERT_KEYS):
        raise ScenarioError("scenario alert values must be non-empty strings")

    gates = value["validation_gates"]
    if not isinstance(gates, list) or len(gates) != 17:
        raise ScenarioError("scenario must contain exactly 17 validation gates")
    labels: list[str] = []
    for row in gates:
        if not isinstance(row, dict) or set(row) != {"validation_gate", "weight"}:
            raise ScenarioError(
                "every validation gate must contain only validation_gate and weight"
            )
        label = row["validation_gate"]
        weight = row["weight"]
        if not isinstance(label, str) or not label:
            raise ScenarioError("validation_gate values must be non-empty strings")
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
            raise ScenarioError("validation-gate weights must be non-negative integers")
        labels.append(label)
    if len(set(labels)) != len(labels):
        raise ScenarioError("validation-gate labels must be unique")
    zero_weight = [row for row in gates if row["weight"] == 0]
    if zero_weight != [{"validation_gate": HARD_FAIL_GATE, "weight": 0}]:
        raise ScenarioError("the disposition row must be the only zero-weight gate")
    if sum(row["weight"] for row in gates) != 100:
        raise ScenarioError("weighted validation gates must total 100")
    return value


def load_scenario(path: Path = SCENARIO_FILE) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioError(f"cannot load scenario declaration {path}: {exc}") from exc
    return validate_scenario(value)


def alert_case_payload(value: dict[str, Any]) -> dict[str, Any]:
    alert = value["alert"]
    return {
        "summary": alert["context"],
        "description": "",
        "status": "new",
        "priority": "unknown",
        "severity": "unknown",
        "payload": {
            "alert_date": alert["alert_date"],
            "source_principal": alert["source_principal"],
            "source_ip": alert["source_ip"],
            "triggering_action": alert["triggering_action"],
        },
    }
