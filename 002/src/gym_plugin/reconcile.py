"""Reconcile the BOTSv3 cases, skills, and agent presets."""

from __future__ import annotations

import json
import os
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from gymctl import agents, presets, tracecat
from gymctl.http import ClientLike


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2]))
AGENT_DIR = ROOT / "benchmark/agent"
EVALS_DIR = ROOT / "benchmark/evals"
SCENARIO_FILE = ROOT / "benchmark/scenario.json"
SKILLS_DIR = AGENT_DIR / "skills"
INVESTIGATOR_SLUG = "gym-002-soc-t1-analyst"
GRADER_SLUG = "gym-002-evaluation-grader"
STATIC_CASE_KEYS = (
    "summary",
    "description",
    "status",
    "priority",
    "severity",
    "payload",
)


class ReconcileError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gym-002] {message}", flush=True)


def request(
    client: ClientLike, method: str, url: str, *, expected=(200,), **kwargs: Any
) -> Any:
    try:
        return tracecat.request_json(client, method, url, expected=expected, **kwargs)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc


def source_cases() -> list[dict[str, Any]]:
    source = json.loads(SCENARIO_FILE.read_text())
    if (
        not isinstance(source, dict)
        or source.get("schema_version") != 2
        or not isinstance(source.get("cases"), list)
    ):
        raise ReconcileError("benchmark/scenario.json is malformed")
    rows = source["cases"]
    alert_ids = [str(row["payload"]["alert_id"]) for row in rows]
    if len(rows) != 20 or len(set(alert_ids)) != 20:
        raise ReconcileError("expected exactly 20 unique BOTSv3 alert cases")
    return rows


def list_managed_case_rows(
    client: ClientLike, workspace_id: str
) -> list[dict[str, Any]]:
    payload = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/cases",
        params={"limit": 100, "include_payload": "true"},
    )
    items = tracecat.paginated_items(payload, "case list")
    return [
        case
        for case in items
        if isinstance(case.get("payload"), dict)
        and case["payload"].get("gym_id") == "002"
    ]


def list_managed_cases(
    client: ClientLike, workspace_id: str
) -> dict[str, dict[str, Any]]:
    managed: dict[str, dict[str, Any]] = {}
    for case in list_managed_case_rows(client, workspace_id):
        data = case.get("payload") or {}
        if not isinstance(data, dict) or data.get("gym_id") != "002":
            continue
        alert_id = str(data.get("alert_id") or "")
        if not alert_id:
            raise ReconcileError("managed case has no alert_id")
        if alert_id in managed:
            raise ReconcileError(f"duplicate managed case for {alert_id}")
        managed[alert_id] = case
    return managed


def case_sessions(
    client: ClientLike, workspace_id: str, case_id: str
) -> list[dict[str, Any]]:
    payload = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/agent/sessions",
        params={"entity_type": "case", "entity_id": case_id, "limit": 100},
    )
    if not isinstance(payload, list):
        raise ReconcileError("case session list is malformed")
    return [row for row in payload if isinstance(row, dict)]


def reconcile_cases(client: ClientLike, workspace_id: str) -> dict[str, dict[str, Any]]:
    desired_rows = source_cases()
    desired_by_id = {str(row["payload"]["alert_id"]): row for row in desired_rows}
    existing = list_managed_cases(client, workspace_id)
    unknown = sorted(set(existing) - set(desired_by_id))
    if unknown:
        raise ReconcileError(
            f"unexpected gym-owned cases require manual review: {unknown}"
        )
    base = f"/workspaces/{workspace_id}/cases"
    for alert_id, desired in desired_by_id.items():
        current = existing.get(alert_id)
        if current is None:
            request(client, "POST", base, body=desired, expected=(201,))
            log(f"created case {alert_id}")
            continue
        case_id = str(current["id"])
        actual = request(client, "GET", f"{base}/{case_id}")
        sessions = case_sessions(client, workspace_id, case_id)
        drift = [key for key in STATIC_CASE_KEYS if actual.get(key) != desired[key]]
        if drift and sessions:
            log(
                f"preserved investigated case {alert_id}; mutable fields differ: {drift}"
            )
        elif drift:
            request(
                client,
                "PATCH",
                f"{base}/{case_id}",
                body={key: desired[key] for key in drift},
                expected=(204,),
            )
            log(f"repaired case {alert_id}: {drift}")
    final = list_managed_cases(client, workspace_id)
    if set(final) != set(desired_by_id):
        raise ReconcileError(
            "managed case queue does not exactly match the 20 source alerts"
        )
    log("case queue READY: 20 cases")
    return final


def reconcile_skills(client: ClientLike, workspace_id: str) -> list[str]:
    skill_ids = presets.reconcile_skills(
        client,
        workspace_id,
        SKILLS_DIR,
        managed_preset_slugs={INVESTIGATOR_SLUG, GRADER_SLUG},
        expected_count=7,
        logger=log,
    )
    log("skills READY: 7 published and verified")
    return skill_ids


def desired_presets(
    client: ClientLike, workspace_id: str, skill_ids: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    investigator_manifest, investigator_prompt = presets.load_manifest(
        AGENT_DIR, "investigator-preset.json"
    )
    if investigator_manifest.get("model_selection") != "organization_default":
        raise ReconcileError("investigator must use organization_default")
    try:
        investigator_model = tracecat.default_agent_model(client)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc
    investigator_desired = presets.preset_payload(
        investigator_manifest, investigator_prompt, investigator_model, skill_ids
    )
    grader_manifest, grader_prompt = presets.load_manifest(
        EVALS_DIR, "grader-preset.json"
    )
    grader_model = presets.workspace_model(
        client,
        workspace_id,
        str(grader_manifest["model_provider"]),
        str(grader_manifest["model_name"]),
    )
    grader_desired = presets.preset_payload(
        grader_manifest, grader_prompt, grader_model, []
    )
    return investigator_desired, grader_desired


def reconcile_presets(
    client: ClientLike, workspace_id: str, skill_ids: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    investigator_desired, grader_desired = desired_presets(
        client, workspace_id, skill_ids
    )
    investigator = presets.reconcile_preset(
        client,
        workspace_id,
        investigator_desired,
    )
    log(f"preset READY: {investigator_desired['slug']}")
    grader = presets.reconcile_preset(
        client,
        workspace_id,
        grader_desired,
    )
    log(f"preset READY: {grader_desired['slug']}")
    if grader.get("actions") or grader.get("mcp_integrations") or grader.get("skills"):
        raise ReconcileError("grader must remain tool-free")
    return investigator, grader


def enrichment_status(client: ClientLike, workspace_id: str) -> dict[str, bool]:
    rows = request(client, "GET", f"/workspaces/{workspace_id}/secrets")
    if not isinstance(rows, list):
        raise ReconcileError("secret inventory response is malformed")
    inventory = {
        str(row.get("name")): set(row.get("keys") or [])
        for row in rows
        if isinstance(row, dict)
    }
    return {
        "urlscan": "URLSCAN_API_KEY" in inventory.get("urlscan", set()),
        "virustotal": "VIRUSTOTAL_API_KEY" in inventory.get("virustotal", set()),
    }


def reconcile() -> None:
    with tracecat.client() as client:
        request(client, "GET", "/health")
        workspace_id = tracecat.login(client)
        try:
            tracecat.verify_entitlements(client)
        except tracecat.TracecatError as exc:
            raise ReconcileError(str(exc)) from exc
        reconcile_cases(client, workspace_id)
        skill_ids = reconcile_skills(client, workspace_id)
        reconcile_presets(client, workspace_id, skill_ids)
        status = enrichment_status(client, workspace_id)
    log(
        f"READY: URLscan={'configured' if status['urlscan'] else 'pending'} VirusTotal={'configured' if status['virustotal'] else 'pending'}"
    )


def status(
    client: ClientLike | None = None,
    email: str | None = None,
    password: str | None = None,
) -> None:
    context = tracecat.client() if client is None else nullcontext(client)
    with context as client:
        request(client, "GET", "/health")
        workspace_id = tracecat.login(client, email, password)
        cases = list_managed_cases(client, workspace_id)
        desired_cases = {str(row["payload"]["alert_id"]): row for row in source_cases()}
        if set(cases) != set(desired_cases):
            raise ReconcileError(
                "managed case IDs do not exactly match the source queue"
            )
        investigated = 0
        for alert_id, case in cases.items():
            actual = request(
                client,
                "GET",
                f"/workspaces/{workspace_id}/cases/{case['id']}",
            )
            sessions = case_sessions(client, workspace_id, str(case["id"]))
            immutable = ("summary", "priority", "severity", "payload")
            drift = [
                key
                for key in immutable
                if actual.get(key) != desired_cases[alert_id][key]
            ]
            if drift:
                raise ReconcileError(
                    f"case {alert_id} drifted immutable fields: {drift}"
                )
            if sessions:
                investigated += 1
            elif any(
                actual.get(key) != desired_cases[alert_id][key]
                for key in STATIC_CASE_KEYS
            ):
                raise ReconcileError(f"pristine case {alert_id} has drifted")

        skills = tracecat.paginated_items(
            request(
                client,
                "GET",
                f"/workspaces/{workspace_id}/agent/skills",
                params={"limit": 100},
            ),
            "skill list",
        )
        skill_ids: list[str] = []
        for directory in sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir()):
            matches = [
                row
                for row in skills
                if row.get("name") == directory.name
                or row.get("slug") == directory.name
            ]
            if len(matches) != 1 or not presets.skill_matches(
                client, workspace_id, matches[0], directory
            ):
                raise ReconcileError(
                    f"managed skill {directory.name} is missing or drifted"
                )
            skill_ids.append(str(matches[0]["id"]))

        for desired in desired_presets(client, workspace_id, skill_ids):
            presets.verify_preset(client, workspace_id, desired)
        enrichments = enrichment_status(client, workspace_id)
    print(
        f"cases={len(cases)}/20 investigated={investigated} skills={len(skill_ids)}/7 "
        "investigator=ready grader=ready "
        f"urlscan={'configured' if enrichments['urlscan'] else 'pending'} "
        f"virustotal={'configured' if enrichments['virustotal'] else 'pending'}"
    )


def reset_managed_evaluations() -> None:
    with tracecat.client() as client:
        request(client, "GET", "/health")
        workspace_id = tracecat.login(client)
        removed_grader_sessions = agents.delete_preset_sessions(
            client,
            workspace_id,
            preset_slug=GRADER_SLUG,
            title_prefix="Gym 002 grader ",
        )
        cases = list_managed_case_rows(client, workspace_id)
        for case in cases:
            payload = case.get("payload") or {}
            alert_id = str(payload.get("alert_id") or case.get("id") or "unknown")
            case_id = str(case["id"])
            for session in case_sessions(client, workspace_id, case_id):
                session_id = session.get("id")
                if session_id:
                    request(
                        client,
                        "DELETE",
                        f"/workspaces/{workspace_id}/agent/sessions/{session_id}",
                        expected=(204, 404),
                    )
            request(
                client,
                "DELETE",
                f"/workspaces/{workspace_id}/cases/{case_id}",
                expected=(204, 404),
            )
            log(f"removed managed evaluation state for {alert_id}")
        reconcile_cases(client, workspace_id)
    log(
        "managed cases and case-scoped investigations were reset; providers, integrations, skills, and presets were retained"
        f"; removed_grader_sessions={removed_grader_sessions}"
    )
