"""Deterministic, evidence-bound scoring for Gym 002 investigations."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from .duckdb_scope import audit_sql_source_scope
from .eval_contracts import CaseContract, REF_RE


DUCKDB_TOOL = "core.duckdb.execute_sql"
# Membership sets rather than ordinals: CasePriority and CaseSeverity do not
# share a scale, and CasePriority.OTHER is 99 without being "above medium".
ABOVE_MEDIUM_PRIORITY = frozenset({"high", "critical"})
ABOVE_MEDIUM_SEVERITY = frozenset({"high", "critical"})
TERMINAL_STATUSES = frozenset({"resolved", "closed"})
URLSCAN_TOOLS = {
    "tools.urlscan.search_scans",
    "tools.urlscan.get_result",
}


def _audit_duckdb_call(
    call: dict[str, Any], exact_url: str
) -> tuple[bool, list[str], str]:
    payload = call.get("input")
    if not isinstance(payload, dict) or set(payload) != {"sql"}:
        return False, [], "DuckDB input must contain only one sql field"
    sql = payload.get("sql")
    if not isinstance(sql, str) or not sql.strip():
        return False, [], "DuckDB sql must be a non-empty string"
    try:
        urls, reason = audit_sql_source_scope(sql, exact_url)
    except ValueError as exc:
        return False, [], str(exc)
    return True, urls, reason


def _successful(call: dict[str, Any]) -> bool:
    return (
        call.get("state") == "output-available"
        and not call.get("error")
        and call.get("output") is not None
    )


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _virustotal_tool(target: str) -> str:
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "tools.virustotal.lookup_domain"
    return "tools.virustotal.lookup_ip_address"


def _tag_names(case: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for tag in case.get("tags") or []:
        if isinstance(tag, dict) and isinstance(tag.get("name"), str):
            names.append(tag["name"])
        elif isinstance(tag, str):
            names.append(tag)
    return names


def _requires_escalation(canonical_case: dict[str, Any]) -> bool:
    """Whether the case must be escalated rather than closed.

    Read from the pinned canonical case, not the live one, so a mutated
    priority or severity cannot change which terminal state is expected.
    """
    return (
        str(canonical_case.get("priority")) in ABOVE_MEDIUM_PRIORITY
        or str(canonical_case.get("severity")) in ABOVE_MEDIUM_SEVERITY
    )


def _assignee_email(case: dict[str, Any]) -> str | None:
    assignee = case.get("assignee")
    if not isinstance(assignee, dict):
        return None
    email = assignee.get("email")
    return str(email) if email else None


def _case_text(snapshot: dict[str, Any]) -> str:
    case = snapshot["case"]
    chunks = [str(case.get("description") or "")]
    chunks.extend(
        str(comment.get("content") or "")
        for comment in snapshot["comments"]
        if isinstance(comment, dict)
    )
    return "\n".join(chunks)


def deterministic_determinations(
    contract: CaseContract,
    calls: list[dict[str, Any]],
    after: dict[str, Any],
    *,
    escalation_assignee: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    exact_url = contract["canonical_case"]["payload"]["event_object_url"]
    all_duck_calls = [call for call in calls if call.get("tool_name") == DUCKDB_TOOL]
    source_audits = []
    for index, call in enumerate(all_duck_calls, start=1):
        allowed, object_urls, reason = _audit_duckdb_call(call, exact_url)
        source_audits.append(
            {
                "call_number": index,
                "allowed": allowed,
                "object_urls": object_urls,
                "reason": reason,
            }
        )
    queried_object_urls = {
        url for audit in source_audits for url in audit["object_urls"]
    }
    unexpected_object_urls = queried_object_urls - {exact_url}
    rejected_scope_calls = [
        audit["call_number"] for audit in source_audits if not audit["allowed"]
    ]
    duck_calls = [
        call
        for call, audit in zip(all_duck_calls, source_audits, strict=True)
        if audit["allowed"] and _successful(call)
    ]
    returned_refs = {
        match
        for call in duck_calls
        for match in REF_RE.findall(_json_text(call.get("output")))
        if match not in set(REF_RE.findall(_json_text(call.get("input"))))
    }
    anchor_refs = set(contract["anchor_event_refs"])
    verified_refs = returned_refs & anchor_refs
    final_text = _case_text(after)
    cited_refs = {ref for ref in verified_refs if ref in final_text}
    tags = _tag_names(after["case"])
    verdict_tags = [tag for tag in tags if tag.startswith("verdict:")]
    incident_tags = [tag for tag in tags if tag.startswith("incident:")]
    expected_verdict = "verdict:" + contract["expected_determination"].replace("_", "-")
    expected_incident = "incident:" + contract["expected_incident_relevance"]
    status_value = after["case"].get("status")
    closed = status_value == "closed"
    escalate = _requires_escalation(contract["canonical_case"])
    assignee_email = _assignee_email(after["case"])
    if escalate:
        # Above-medium cases are escalated for further analysis, so the correct
        # end state is assigned to the analyst and still open.
        terminal_state_met = (
            status_value not in TERMINAL_STATUSES
            and assignee_email == escalation_assignee
        )
    else:
        terminal_state_met = closed

    observations = {
        "exact_object_url": exact_url,
        "queried_botsv3_object_urls": sorted(queried_object_urls),
        "unexpected_botsv3_object_urls": sorted(unexpected_object_urls),
        "rejected_duckdb_source_call_numbers": rejected_scope_calls,
        "duckdb_source_audits": source_audits,
        "successful_exact_object_queries": len(duck_calls),
        "returned_event_refs": sorted(returned_refs),
        "required_anchor_event_refs": contract["anchor_event_refs"],
        "verified_anchor_event_refs": sorted(verified_refs),
        "cited_verified_event_refs": sorted(cited_refs),
        "verdict_tags": verdict_tags,
        "incident_tags": incident_tags,
        "case_closed": closed,
        "case_status": status_value,
        "case_assignee_email": assignee_email,
        "requires_escalation": escalate,
        "expected_terminal_state": (
            f"assigned to {escalation_assignee} and not {sorted(TERMINAL_STATUSES)}"
            if escalate
            else "closed"
        ),
        "terminal_state_met": terminal_state_met,
    }
    outcomes = {
        "determination": "met" if verdict_tags == [expected_verdict] else "missed",
        "incident_relevance": "met"
        if incident_tags == [expected_incident]
        else "missed",
        "exact_object": "met"
        if duck_calls and not unexpected_object_urls and not rejected_scope_calls
        else "missed",
        "case_evidence": "met"
        if terminal_state_met
        and cited_refs
        and len(verdict_tags) == 1
        and len(incident_tags) == 1
        else "missed",
    }
    targets = contract["enrichment_targets"]
    if targets:
        target = targets[0]
        folded_target = target.casefold()
        evidence_derived = any(
            folded_target in _json_text(call.get("output")).casefold()
            for call in duck_calls
        )
        observations["required_enrichment_targets"] = targets
        observations["evidence_derived_enrichment_targets"] = (
            targets if evidence_derived else []
        )
        enrichment_tools = {
            "urlscan": URLSCAN_TOOLS,
            "virustotal": {_virustotal_tool(target)},
        }
        for enrichment, tools in enrichment_tools.items():
            relevant = [
                call
                for call in calls
                if call.get("tool_name") in tools
                and _successful(call)
                and folded_target in _json_text(call.get("input")).casefold()
            ]
            observations[f"successful_matching_{enrichment}_lookups"] = len(relevant)
            outcomes[enrichment] = "met" if evidence_derived and relevant else "missed"
    return outcomes, observations
