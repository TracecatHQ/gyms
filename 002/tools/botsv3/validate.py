"""Cross-file validation for generated BOTSv3 benchmark artifacts."""

from __future__ import annotations

import re
from typing import Any

from gymctl.evidence import EVENT_REF_VERSION

from .model import SpecError


REF_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_outputs(scenario: dict[str, Any], contracts: dict[str, Any]) -> None:
    if set(scenario) != {"schema_version", "event_ref_version", "cases"}:
        raise SpecError("generated scenario shape is invalid")
    if set(contracts) != {
        "schema_version",
        "event_ref_version",
        "determination_values",
        "incident_relevance_values",
        "cases",
    }:
        raise SpecError("generated evaluation-contract shape is invalid")
    if scenario["schema_version"] != 2 or contracts["schema_version"] != 2:
        raise SpecError("generated schema versions drifted")
    if (
        scenario["event_ref_version"] != EVENT_REF_VERSION
        or contracts["event_ref_version"] != EVENT_REF_VERSION
    ):
        raise SpecError("generated event-reference version drifted")
    scenario_ids = [row["payload"]["alert_id"] for row in scenario["cases"]]
    contract_ids = [row["alert_id"] for row in contracts["cases"]]
    if (
        scenario_ids != contract_ids
        or len(scenario_ids) != 20
        or len(set(scenario_ids)) != 20
    ):
        raise SpecError("generated case order or identity drifted")
    if any(
        row["payload"]["event_object_key"]
        != row["payload"]["event_object_url"].rsplit("/", 1)[-1]
        for row in scenario["cases"]
    ):
        raise SpecError("generated object key and URL disagree")
    all_refs = [ref for row in contracts["cases"] for ref in row["anchor_event_refs"]]
    if not all_refs or not all(REF_RE.fullmatch(ref) for ref in all_refs):
        raise SpecError("generated anchor event references are invalid")
    enriched = [row for row in contracts["cases"] if row["required_enrichments"]]
    if len(enriched) != 5 or any(
        row["required_enrichments"] != ["urlscan", "virustotal"]
        or not row["enrichment_targets"]
        for row in enriched
    ):
        raise SpecError("generated enrichment contracts drifted")
    if any(
        bool(row["enrichment_targets"]) != bool(row["required_enrichments"])
        for row in contracts["cases"]
    ):
        raise SpecError("generated enrichment targets and requirements disagree")
