"""Resolve every declarative evidence predicate against its exact ZIP member."""

from __future__ import annotations

import gzip
import json
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from gymctl.evidence import event_ref

from .model import SpecError


def _matches(raw: str, terms: list[str]) -> bool:
    folded = raw.casefold()
    return all(term.casefold() in folded for term in terms)


def _embedded_objects(raw: str) -> list[dict[str, Any]]:
    """Decode complete JSON objects embedded in BOTSv3 journal payloads."""

    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    offset = 0
    while True:
        offset = raw.find("{", offset)
        if offset < 0:
            return objects
        try:
            value, end = decoder.raw_decode(raw, offset)
        except json.JSONDecodeError:
            offset += 1
            continue
        if isinstance(value, dict):
            objects.append(value)
        offset = max(offset + 1, end)


def resolve_evidence(
    archive_path: Path, cases: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Return ordered anchor identities after proving exact and absent predicates."""

    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        by_object[case["evidence"]["object_key"]].append(case)
    resolved: dict[str, list[dict[str, Any]]] = {}
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SpecError(f"cannot open BOTSv3 archive {archive_path}: {exc}") from exc
    with archive:
        available = set(archive.namelist())
        for object_key, object_cases in by_object.items():
            member = f"botsv3/{object_key}"
            if member not in available:
                raise SpecError(f"archive is missing selected evidence object {member}")
            anchor_hits: dict[tuple[str, int], list[dict[str, Any]]] = {
                (case["alert_id"], index): []
                for case in object_cases
                for index in range(len(case["evidence"]["anchors"]))
            }
            absence_hits: dict[tuple[str, int], int] = {
                (case["alert_id"], index): 0
                for case in object_cases
                for index in range(len(case["evidence"].get("absent_events", [])))
            }
            with (
                archive.open(member) as compressed,
                gzip.GzipFile(fileobj=compressed) as stream,
            ):
                for line_number, raw_line in enumerate(stream, start=1):
                    if not raw_line.strip():
                        continue
                    try:
                        event = json.loads(raw_line)
                    except json.JSONDecodeError as exc:
                        raise SpecError(
                            f"{object_key}:{line_number} is not valid JSON"
                        ) from exc
                    event_time = str(event.get("_time") or "")
                    raw = event.get("_raw")
                    if not isinstance(raw, str):
                        raise SpecError(
                            f"{object_key}:{line_number} has no string _raw field"
                        )
                    embedded: list[dict[str, Any]] | None = None
                    for case in object_cases:
                        alert_id = case["alert_id"]
                        for index, anchor in enumerate(case["evidence"]["anchors"]):
                            if event_time.startswith(
                                anchor["time_prefix"]
                            ) and _matches(raw, anchor["all_terms"]):
                                anchor_hits[(alert_id, index)].append(
                                    {
                                        "event_ref": event_ref(
                                            object_key, line_number, raw_line
                                        ),
                                        "line_number": line_number,
                                        "event_time": event_time,
                                    }
                                )
                        predicates = case["evidence"].get("absent_events", [])
                        if predicates and embedded is None:
                            embedded = _embedded_objects(raw)
                        for index, predicate in enumerate(predicates):
                            expected_fields = predicate["fields"]
                            absence_hits[(alert_id, index)] += sum(
                                all(
                                    event.get(key) == value
                                    for key, value in expected_fields.items()
                                )
                                for event in embedded or []
                            )

            for case in object_cases:
                alert_id = case["alert_id"]
                rows: list[dict[str, Any]] = []
                for index in range(len(case["evidence"]["anchors"])):
                    hits = anchor_hits[(alert_id, index)]
                    if len(hits) != 1:
                        raise SpecError(
                            f"{alert_id} anchor {index + 1} matched {len(hits)} rows "
                            f"in {object_key}; expected exactly one"
                        )
                    rows.append(hits[0])
                for index in range(len(case["evidence"].get("absent_events", []))):
                    count = absence_hits[(alert_id, index)]
                    if count:
                        raise SpecError(
                            f"{alert_id} absence predicate {index + 1} matched {count} "
                            f"rows in {object_key}; expected none"
                        )
                resolved[alert_id] = rows
    if set(resolved) != {case["alert_id"] for case in cases}:
        raise SpecError("not every case resolved to evidence")
    return resolved
