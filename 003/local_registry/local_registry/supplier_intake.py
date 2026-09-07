"""Tracecat-native, fixed-target security actions for supplier intake."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from tracecat_registry import RegistrySecret, ctx, registry


NAMESPACE = "security.supplier_intake"
GYM_ID = "003"
SCENARIO = "supplier-intake"
ASSET = "supplier.intake.test"
CVE = "CVE-2026-21858"
DEDUP_KEY = f"{SCENARIO}|{ASSET}|{CVE}"
ROUTE = "/form/supplier-intake"
METHOD = "POST"
ALLOWED_CONTENT_TYPE = "multipart/form-data"
PROPOSAL_REVISION = 1
NUCLEI_BINARY = "/usr/local/bin/nuclei"
IMPLEMENTATION_MARKER = "supplier-intake-actions-v4"

N8N_SECRET = RegistrySecret(
    name="supplier_intake_n8n",
    keys=["GYM_N8N_STAFF_EMAIL", "GYM_N8N_STAFF_PASSWORD"],
)
WAF_SECRET = RegistrySecret(
    name="supplier_intake_waf",
    keys=["BUNKERWEB_API_USERNAME", "BUNKERWEB_API_TOKEN"],
)


def _execution_context() -> dict[str, Any]:
    run_id = f"run-{uuid.uuid4()}"
    evidence_dir = Path("/var/lib/gym/jobs") / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    return {
        "run_id": run_id,
        "scenario": SCENARIO,
        "asset": "supplier.intake.test",
        "ingress": "http://bunkerweb:8080",
        "host_header": "supplier.intake.test",
        "host": "supplier.intake.test",
        "evidence_dir": evidence_dir,
        "state_dir": Path("/var/lib/gym/state"),
        "timeout": 60,
        "started_at": datetime.now(UTC).isoformat(),
    }


def _case_payload(case_id: str) -> dict[str, Any]:
    """Resolve the managed incident case and return a defensive payload copy."""

    case = ctx.cases.get_case(case_id)
    if str(case.get("id")) != case_id:
        raise ValueError("case identity mismatch")
    payload = case.get("payload")
    payload = dict(payload) if isinstance(payload, dict) else {}
    expected = {
        "gym_id": GYM_ID,
        "dedup_key": DEDUP_KEY,
        "scenario": SCENARIO,
        "asset": ASSET,
        "cve": CVE,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise ValueError("case is not the managed supplier intake incident")
    return payload


def _proposal_digest(proposal: dict[str, Any]) -> str:
    signed = {
        key: proposal[key]
        for key in (
            "scenario",
            "revision",
            "route",
            "method",
            "allowed_content_type",
            "recommended_mode",
            "rationale",
        )
    }
    canonical = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _validated_stored_proposal(value: Any) -> dict[str, Any]:
    """Reject altered, stale, or expanded proposals before a state change."""

    from gym_plugin.policy import validate_proposal

    if not isinstance(value, dict):
        raise ValueError("the case has no reviewed firewall proposal")
    expected_keys = {
        "scenario",
        "revision",
        "route",
        "method",
        "allowed_content_type",
        "recommended_mode",
        "rationale",
        "proposal_id",
        "created_at",
    }
    if set(value) != expected_keys:
        raise ValueError("the stored firewall proposal has unknown or missing fields")
    validate_proposal(
        {
            key: value[key]
            for key in (
                "scenario",
                "revision",
                "route",
                "method",
                "allowed_content_type",
            )
        },
        expected_revision=PROPOSAL_REVISION,
    )
    if value.get("recommended_mode") not in {"BLOCK", "LOG_ONLY"}:
        raise ValueError("the stored firewall proposal has an invalid mode")
    rationale = value.get("rationale")
    if not isinstance(rationale, str) or not 20 <= len(rationale) <= 2_000:
        raise ValueError("the stored firewall proposal has an invalid rationale")
    proposal_id = value.get("proposal_id")
    if not isinstance(proposal_id, str) or not hmac.compare_digest(
        proposal_id, _proposal_digest(value)
    ):
        raise ValueError("the stored firewall proposal integrity check failed")
    created_at = value.get("created_at")
    if not isinstance(created_at, str):
        raise ValueError("the stored firewall proposal has an invalid timestamp")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("the stored firewall proposal has an invalid timestamp") from exc
    return dict(value)


def _evidence_refs(paths: list[str]) -> list[str]:
    return [Path(path).name for path in paths]


def _safe_verification(result: dict[str, Any], run_id: str) -> dict[str, Any]:
    cleanup = result.get("cleanup") if isinstance(result.get("cleanup"), dict) else {}
    return {
        "run_id": run_id,
        "verdict": result.get("verdict", "inconclusive"),
        "cleanup": {
            "status": cleanup.get("status"),
            "workflow_removed": cleanup.get("workflow_removed"),
        },
        "evidence_refs": _evidence_refs(list(result.get("evidence") or [])),
        "error": result.get("error"),
    }


@registry.register(
    default_title="Scan supplier intake",
    display_group="Supplier intake response",
    namespace=NAMESPACE,
    description=(
        "Run the pinned Nuclei template against the fixed supplier intake ingress. "
        "The caller cannot provide a target, template, header, or command. "
        f"Implementation: {IMPLEMENTATION_MARKER}."
    ),
)
def scan(case_id: str) -> dict[str, Any]:
    """Return a sanitized version-finding result for the supplied case."""

    from gym_plugin.scanner import run_scan

    _case_payload(case_id)
    if shutil.which("nuclei") != NUCLEI_BINARY:
        raise RuntimeError("the pinned scanner executable is unavailable")
    execution = _execution_context()
    result = run_scan(execution)
    finding = result.get("finding") if isinstance(result.get("finding"), dict) else None
    return {
        "case_id": case_id,
        "run_id": execution["run_id"],
        "verdict": result.get("verdict", "inconclusive"),
        "finding": finding,
        "evidence_refs": _evidence_refs(list(result.get("evidence") or [])),
        "error": result.get("error"),
    }


@registry.register(
    default_title="Verify supplier intake exploitability",
    display_group="Supplier intake response",
    namespace=NAMESPACE,
    description=(
        "Run fixed active verification and required benign transactions against the "
        "supplier intake ingress. The caller cannot provide exploit material or a target."
    ),
    secrets=[N8N_SECRET],
)
def verify(case_id: str) -> dict[str, Any]:
    """Return sanitized impact, cleanup, and compatibility evidence."""

    from gym_plugin.operation_lock import exclusive_operation
    from gym_plugin.probe import verify as run_verification
    from gym_plugin.traffic import run_benign_suite

    _case_payload(case_id)
    execution = _execution_context()
    with exclusive_operation(execution["state_dir"]):
        attack = run_verification(execution)
        benign = run_benign_suite(execution)
    safe_attack = _safe_verification(attack, str(execution["run_id"]))
    return {
        "case_id": case_id,
        **safe_attack,
        "benign": {
            "passed": benign.get("passed") is True,
            "transactions": [
                {
                    "name": row.get("name"),
                    "status": row.get("status"),
                    "passed": row.get("passed"),
                }
                for row in benign.get("transactions", [])
                if isinstance(row, dict)
            ],
            "evidence_refs": _evidence_refs(list(benign.get("evidence") or [])),
        },
    }


@registry.register(
    default_title="Record supplier intake firewall proposal",
    display_group="Supplier intake response",
    namespace=NAMESPACE,
    description=(
        "Validate and persist one immutable, route-scoped firewall proposal on the case. "
        "Policy fields are constrained to the reviewed supplier intake boundary."
    ),
)
def propose_policy(
    case_id: str,
    recommended_mode: Literal["BLOCK", "LOG_ONLY"],
    rationale: str,
    route: Literal["/form/supplier-intake"] = ROUTE,
    method: Literal["POST"] = METHOD,
    allowed_content_type: Literal["multipart/form-data"] = ALLOWED_CONTENT_TYPE,
) -> dict[str, Any]:
    """Persist and return the exact policy later consumed by the human workflow."""

    payload = _case_payload(case_id)

    from gym_plugin.policy import validate_proposal

    if not 20 <= len(rationale.strip()) <= 2_000:
        raise ValueError("rationale must contain 20 to 2000 characters")
    policy = validate_proposal(
        {
            "scenario": SCENARIO,
            "revision": PROPOSAL_REVISION,
            "route": route,
            "method": method,
            "allowed_content_type": allowed_content_type,
        },
        expected_revision=PROPOSAL_REVISION,
    )
    proposal = {
        **policy.as_dict(),
        "recommended_mode": recommended_mode,
        "rationale": rationale.strip(),
    }
    proposal["proposal_id"] = _proposal_digest(proposal)
    proposal["created_at"] = datetime.now(UTC).isoformat()

    existing = payload.get("firewall_proposal")
    if isinstance(existing, dict):
        checked = _validated_stored_proposal(existing)
        if checked["proposal_id"] != proposal["proposal_id"]:
            raise ValueError("an immutable firewall proposal already exists for this case")
        return checked
    payload["firewall_proposal"] = proposal
    ctx.cases.update_case_simple(case_id, payload=payload)
    return proposal


@registry.register(
    default_title="Apply reviewed supplier intake firewall policy",
    display_group="Supplier intake response",
    namespace=NAMESPACE,
    description=(
        "Apply the exact proposal stored on the case, verify activation and required "
        "traffic, and restore the previous firewall state on failure."
    ),
    secrets=[N8N_SECRET, WAF_SECRET],
    requires_approval=True,
)
def apply_reviewed_policy(
    case_id: str,
    task_id: str,
    proposal_revision: Literal[1],
    mode: Literal["BLOCK", "LOG_ONLY"],
) -> dict[str, Any]:
    """Execute a reviewed proposal; this action is intentionally absent from the Agent."""

    from gym_plugin.operation_lock import exclusive_operation
    from gym_plugin.rule_application import apply_rule

    payload = _case_payload(case_id)
    proposal = _validated_stored_proposal(payload.get("firewall_proposal"))
    if proposal.get("revision") != proposal_revision:
        raise ValueError("the case firewall proposal revision does not match the task")
    task = ctx.cases.get_task(task_id)
    if str(task.get("case_id")) != case_id:
        raise ValueError("the reviewed task does not belong to this case")
    expected_title = "Create BLOCK rule" if mode == "BLOCK" else "Create LOG-only rule"
    trigger_values = task.get("default_trigger_values")
    if task.get("title") != expected_title or not isinstance(trigger_values, dict):
        raise ValueError("the reviewed task does not authorize this firewall mode")
    expected_trigger = {
        "case_id": case_id,
        "scenario": SCENARIO,
        "proposal_revision": proposal_revision,
        "mode": mode,
    }
    if any(trigger_values.get(key) != value for key, value in expected_trigger.items()):
        raise ValueError("the reviewed task inputs do not match this firewall request")
    execution = _execution_context()
    request = {
        "case_id": case_id,
        "task_id": task_id,
        "scenario": SCENARIO,
        "proposal_revision": proposal_revision,
        "mode": mode,
        "proposal": {
            key: proposal[key]
            for key in ("scenario", "revision", "route", "method", "allowed_content_type")
        },
    }
    with exclusive_operation(execution["state_dir"]):
        result = apply_rule(execution, request)
    return {
        "case_id": case_id,
        "task_id": task_id,
        "run_id": execution["run_id"],
        "proposal_id": proposal["proposal_id"],
        "proposal_revision": proposal_revision,
        "mode": mode,
        "verdict": result.get("verdict"),
        "rule_id": result.get("rule_id"),
        "before_verdict": result.get("before_verdict"),
        "after_verdict": result.get("after_verdict"),
        "benign": {
            "passed": (result.get("benign") or {}).get("passed") is True,
            "transactions": [
                {
                    "name": row.get("name"),
                    "status": row.get("status"),
                    "passed": row.get("passed"),
                }
                for row in (result.get("benign") or {}).get("transactions", [])
                if isinstance(row, dict)
            ],
        },
        "waf_events": [
            {
                "timestamp": event.get("timestamp"),
                "rule_id": event.get("rule_id"),
                "mode": event.get("mode"),
                "audit_correlated": event.get("audit_correlated") is True,
                "blocked": event.get("blocked") is True,
            }
            for event in (result.get("waf_events") or [])
            if isinstance(event, dict)
        ],
        "rollback": result.get("rollback") or {},
    }
