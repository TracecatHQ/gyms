"""Shared strict binary-gate protocol for gym evaluators."""

from __future__ import annotations

import json
import re
from typing import Any


class EvaluationProtocolError(RuntimeError):
    pass


def parse_binary_judgment(text: str, gates: list[str]) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.I)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise EvaluationProtocolError(
            f"grader response was malformed JSON: {exc}"
        ) from exc
    return validate_binary_judgment(payload, gates)


def validate_binary_judgment(payload: Any, gates: list[str]) -> dict[str, Any]:
    """Validate an already-decoded, ordered binary-gate response."""

    if not isinstance(payload, dict) or set(payload) != {"determinations"}:
        raise EvaluationProtocolError(
            "grader response must contain only determinations"
        )
    rows = payload["determinations"]
    if not isinstance(rows, list) or len(rows) != len(gates):
        raise EvaluationProtocolError(
            "grader response has the wrong number of determinations"
        )
    normalized: list[dict[str, str]] = []
    for index, (row, gate) in enumerate(zip(rows, gates, strict=True), start=1):
        if not isinstance(row, dict) or set(row) != {
            "validation_gate",
            "determination",
        }:
            raise EvaluationProtocolError(
                f"grader determination {index} has an invalid shape"
            )
        if row["validation_gate"] != gate:
            raise EvaluationProtocolError(
                f"grader determination {index} changed or reordered a gate"
            )
        if row["determination"] not in {"met", "missed"}:
            raise EvaluationProtocolError(
                f"grader determination {index} is not met or missed"
            )
        normalized.append(
            {"validation_gate": gate, "determination": row["determination"]}
        )
    return {"determinations": normalized}
