"""Render the public case queue and private evaluation contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gymctl.evidence import EVENT_REF_VERSION


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def render(
    cases: list[dict[str, Any]], resolved: dict[str, list[dict[str, Any]]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    scenario_rows: list[dict[str, Any]] = []
    contract_rows: list[dict[str, Any]] = []
    for case in cases:
        alert_id = case["alert_id"]
        public = case["public"]
        object_key = case["evidence"]["object_key"]
        scenario_rows.append(
            {
                "summary": public["summary"],
                "description": public["description"],
                "status": "new",
                "priority": "high"
                if public["severity"] in {"high", "critical"}
                else "medium",
                "severity": public["severity"],
                "payload": {
                    "gym_id": "002",
                    "alert_id": alert_id,
                    "event_ref_version": EVENT_REF_VERSION,
                    "event_object_key": object_key,
                    "event_object_url": f"http://minio:9000/botsv3/{object_key}",
                    "alert": public,
                },
            }
        )
        oracle = case["oracle"]
        contract_rows.append(
            {
                "alert_id": alert_id,
                "expected_determination": oracle["determination"],
                "expected_incident_relevance": oracle["incident_relevance"],
                "basis": oracle["basis"],
                "event_object_key": object_key,
                "anchor_event_refs": [row["event_ref"] for row in resolved[alert_id]],
                "required_enrichments": oracle["required_enrichments"],
                "enrichment_targets": oracle.get("enrichment_targets", []),
            }
        )
    scenario = {
        "schema_version": 2,
        "event_ref_version": EVENT_REF_VERSION,
        "cases": scenario_rows,
    }
    contracts = {
        "schema_version": 2,
        "event_ref_version": EVENT_REF_VERSION,
        "determination_values": ["true_positive", "false_positive"],
        "incident_relevance_values": ["related", "unrelated"],
        "cases": contract_rows,
    }
    return scenario, contracts


def write_outputs(
    output_root: Path, scenario: dict[str, Any], contracts: dict[str, Any]
) -> None:
    targets = {
        output_root / "benchmark/scenario.json": scenario,
        output_root / "benchmark/evals/cases.json": contracts,
    }
    for path, value in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_text(value))
