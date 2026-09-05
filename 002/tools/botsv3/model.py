"""Strict schema validation for the hand-audited BOTSv3 case specification."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


PUBLIC_KEYS = {
    "provider",
    "product",
    "alert_type",
    "summary",
    "description",
    "severity",
    "resource",
    "event_time",
    "attributes",
}
ORACLE_KEYS = {
    "determination",
    "incident_relevance",
    "basis",
    "required_enrichments",
}
OBJECT_RE = re.compile(r"^botsv3_2018-08-(?:17|18|19|20|21)_\d{2}\.jsonl\.gz$")
TIME_RE = re.compile(r"^2018-08-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$")


class SpecError(RuntimeError):
    pass


def _object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise SpecError(f"{label} has invalid keys: {observed}")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise SpecError(f"{label} must be a non-empty trimmed string")
    return value


def _predicate(value: Any, label: str, *, timed: bool) -> dict[str, Any]:
    keys = {"time_prefix", "all_terms"} if timed else {"all_terms"}
    row = _object(value, label, keys)
    if timed and not TIME_RE.fullmatch(
        _text(row["time_prefix"], f"{label}.time_prefix")
    ):
        raise SpecError(f"{label}.time_prefix is invalid")
    terms = row["all_terms"]
    if (
        not isinstance(terms, list)
        or not terms
        or len(set(terms)) != len(terms)
        or not all(isinstance(term, str) and term for term in terms)
    ):
        raise SpecError(f"{label}.all_terms must contain unique non-empty strings")
    return row


def load_specs(path: Path) -> list[dict[str, Any]]:
    try:
        root = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SpecError(f"cannot load {path}: {exc}") from exc
    _object(root, "specification", {"schema_version", "cases"})
    if root["schema_version"] != 2 or isinstance(root["schema_version"], bool):
        raise SpecError("specification schema_version must be 2")
    cases = root["cases"]
    if not isinstance(cases, list):
        raise SpecError("specification cases must be a list")
    ids = [row.get("alert_id") if isinstance(row, dict) else None for row in cases]
    if (
        len(ids) != 20
        or not all(isinstance(alert_id, str) and alert_id.strip() for alert_id in ids)
        or len(set(ids)) != 20
    ):
        raise SpecError("specification must contain 20 uniquely identified cases")

    distribution: dict[tuple[str, str], int] = {}
    enrichment_count = 0
    for index, value in enumerate(cases):
        label = f"cases[{index}]"
        row = _object(value, label, {"alert_id", "public", "evidence", "oracle"})
        _text(row["alert_id"], f"{label}.alert_id")

        public = _object(row["public"], f"{label}.public", PUBLIC_KEYS)
        for key in PUBLIC_KEYS - {"attributes"}:
            _text(public[key], f"{label}.public.{key}")
        if public["severity"] not in {"low", "medium", "high", "critical"}:
            raise SpecError(f"{label}.public.severity is invalid")
        if not TIME_RE.fullmatch(public["event_time"]):
            raise SpecError(f"{label}.public.event_time is invalid")
        if not isinstance(public["attributes"], dict) or not public["attributes"]:
            raise SpecError(f"{label}.public.attributes must be a non-empty object")

        evidence = row["evidence"]
        if not isinstance(evidence, dict) or not {"object_key", "anchors"} <= set(
            evidence
        ):
            raise SpecError(f"{label}.evidence is malformed")
        if set(evidence) - {"object_key", "anchors", "absent_events"}:
            raise SpecError(f"{label}.evidence has unknown fields")
        if not OBJECT_RE.fullmatch(
            _text(evidence["object_key"], f"{label}.evidence.object_key")
        ):
            raise SpecError(f"{label}.evidence.object_key is invalid")
        anchors = evidence["anchors"]
        if not isinstance(anchors, list) or not anchors:
            raise SpecError(f"{label}.evidence.anchors must be non-empty")
        for offset, anchor in enumerate(anchors):
            _predicate(anchor, f"{label}.evidence.anchors[{offset}]", timed=True)
        absent = evidence.get("absent_events", [])
        if not isinstance(absent, list):
            raise SpecError(f"{label}.evidence.absent_events must be a list")
        for offset, predicate in enumerate(absent):
            item = _object(
                predicate,
                f"{label}.evidence.absent_events[{offset}]",
                {"fields"},
            )
            if not isinstance(item["fields"], dict) or not item["fields"]:
                raise SpecError(
                    f"{label}.evidence.absent_events[{offset}].fields must be non-empty"
                )

        oracle = row["oracle"]
        if not isinstance(oracle, dict) or set(oracle) not in (
            ORACLE_KEYS,
            ORACLE_KEYS | {"enrichment_targets"},
        ):
            observed = (
                sorted(oracle) if isinstance(oracle, dict) else type(oracle).__name__
            )
            raise SpecError(f"{label}.oracle has invalid keys: {observed}")
        determination = oracle["determination"]
        relevance = oracle["incident_relevance"]
        if determination not in {"true_positive", "false_positive"}:
            raise SpecError(f"{label}.oracle.determination is invalid")
        if relevance not in {"related", "unrelated"}:
            raise SpecError(f"{label}.oracle.incident_relevance is invalid")
        _text(oracle["basis"], f"{label}.oracle.basis")
        required = oracle["required_enrichments"]
        if required not in ([], ["urlscan", "virustotal"]):
            raise SpecError(f"{label}.oracle.required_enrichments is invalid")
        targets = oracle.get("enrichment_targets", [])
        if (
            not isinstance(targets, list)
            or len(targets) != (1 if required else 0)
            or not all(
                isinstance(target, str) and target and target.strip() == target
                for target in targets
            )
            or len(set(targets)) != len(targets)
            or bool(targets) != bool(required)
        ):
            raise SpecError(
                f"{label}.oracle.enrichment_targets must be unique, non-empty, "
                "and present exactly when enrichment is required"
            )
        if required:
            enrichment_count += 1
        distribution[(determination, relevance)] = (
            distribution.get((determination, relevance), 0) + 1
        )

    expected_distribution = {
        ("true_positive", "related"): 17,
        ("false_positive", "related"): 1,
        ("true_positive", "unrelated"): 1,
        ("false_positive", "unrelated"): 1,
    }
    if distribution != expected_distribution:
        raise SpecError(f"truth-axis distribution drifted: {distribution}")
    if enrichment_count != 5:
        raise SpecError(
            f"expected exactly five enrichment cases, found {enrichment_count}"
        )
    return cases
