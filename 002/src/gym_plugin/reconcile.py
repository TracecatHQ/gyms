"""Reconcile the BOTSv3 cases, skills, and agent presets."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import mimetypes
import os
from contextlib import nullcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from gymctl import tracecat


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2]))
AGENT_DIR = ROOT / "benchmark/agent"
EVALS_DIR = ROOT / "benchmark/evals"
ALERTS_FILE = ROOT / "benchmark/scenario/alerts.csv"
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
    client: httpx.Client, method: str, url: str, *, expected=(200,), **kwargs: Any
) -> Any:
    try:
        return tracecat.request_json(client, method, url, expected=expected, **kwargs)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc


def login(
    client: httpx.Client,
    email: str | None = None,
    password: str | None = None,
) -> str:
    try:
        workspace_id = tracecat.login(client, email, password)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc
    client.headers["x-tracecat-role-workspace-id"] = workspace_id
    client.params = {"workspace_id": workspace_id}
    return workspace_id


def source_cases() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with ALERTS_FILE.open(newline="") as stream:
        for row in csv.DictReader(stream):
            event = row["event_time"]
            day, hour = event[:10], event[11:13]
            alert = json.loads(row["payload_json"])
            payload = {
                "gym_id": "002",
                "alert_id": row["alert_id"],
                "provider": row["provider"],
                "product": row["product"],
                "alert_type": row["alert_type"],
                "event_time": event,
                "resource": row["resource"],
                "event_object_url": f"http://minio:9000/botsv3/botsv3_{day}_{hour}.jsonl.gz",
                "alert": alert,
            }
            rows.append(
                {
                    "summary": alert.get("title") or row["alert_type"],
                    "description": alert.get("description")
                    or "Investigate this BOTSv3 alert using its exact event object.",
                    "status": "new",
                    "priority": "high"
                    if row["severity"] in ("high", "critical")
                    else "medium",
                    "severity": row["severity"]
                    if row["severity"] in {"low", "medium", "high", "critical"}
                    else "unknown",
                    "payload": payload,
                }
            )
    alert_ids = [str(row["payload"]["alert_id"]) for row in rows]
    if len(rows) != 34 or len(set(alert_ids)) != 34:
        raise ReconcileError("expected exactly 34 unique BOTSv3 alert cases")
    return rows


def list_managed_cases(
    client: httpx.Client, workspace_id: str
) -> dict[str, dict[str, Any]]:
    payload = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/cases",
        params={"limit": 100, "include_payload": "true"},
    )
    items = tracecat.paginated_items(payload, "case list")
    managed: dict[str, dict[str, Any]] = {}
    for case in items:
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
    client: httpx.Client, workspace_id: str, case_id: str
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


def reconcile_cases(
    client: httpx.Client, workspace_id: str
) -> dict[str, dict[str, Any]]:
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
            "managed case queue does not exactly match the 34 source alerts"
        )
    log("case queue READY: 34 cases")
    return final


def _local_skill_files(directory: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        content_type = mimetypes.guess_type(path.name)[0] or "text/plain"
        files.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "content_base64": base64.b64encode(path.read_bytes()).decode(),
                "content_type": content_type,
            }
        )
    if not files or not any(item["path"] == "SKILL.md" for item in files):
        raise ReconcileError(f"skill {directory.name} has no SKILL.md")
    return files


def _local_skill_hashes(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(item for item in directory.rglob("*") if item.is_file())
    }


def _skill_matches(
    client: httpx.Client, workspace_id: str, skill: dict[str, Any], directory: Path
) -> bool:
    version_id = skill.get("current_version_id")
    if not version_id:
        return False
    version = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/agent/skills/{skill['id']}/versions/{version_id}",
    )
    remote = {
        str(item.get("path")): str(item.get("sha256"))
        for item in version.get("files", [])
        if isinstance(item, dict)
    }
    return remote == _local_skill_hashes(directory)


def _detach_managed_presets(client: httpx.Client, workspace_id: str) -> None:
    base = f"/workspaces/{workspace_id}/agent/presets"
    rows = request(client, "GET", base)
    for preset in rows if isinstance(rows, list) else []:
        if isinstance(preset, dict) and preset.get("slug") in {
            INVESTIGATOR_SLUG,
            GRADER_SLUG,
        }:
            request(client, "PATCH", f"{base}/{preset['id']}", body={"skills": []})


def reconcile_skills(client: httpx.Client, workspace_id: str) -> list[str]:
    base = f"/workspaces/{workspace_id}/agent/skills"
    payload = request(client, "GET", base, params={"limit": 100})
    existing = tracecat.paginated_items(payload, "skill list")
    expected_names = [
        path.name for path in sorted(SKILLS_DIR.iterdir()) if path.is_dir()
    ]
    skill_ids: list[str] = []
    detached = False
    for name in expected_names:
        directory = SKILLS_DIR / name
        matches = [
            row
            for row in existing
            if row.get("name") == name or row.get("slug") == name
        ]
        if len(matches) > 1:
            raise ReconcileError(f"multiple workspace skills match {name}")
        skill = matches[0] if matches else None
        if skill is not None and not _skill_matches(
            client, workspace_id, skill, directory
        ):
            if not detached:
                _detach_managed_presets(client, workspace_id)
                detached = True
            request(client, "DELETE", f"{base}/{skill['id']}", expected=(204,))
            skill = None
            log(f"replaced drifted skill {name}")
        if skill is None:
            skill = request(
                client,
                "POST",
                f"{base}:upload",
                body={"name": name, "files": _local_skill_files(directory)},
                expected=(201,),
            )
        if not skill.get("current_version_id"):
            request(client, "POST", f"{base}/{skill['id']}/publish")
            skill = request(client, "GET", f"{base}/{skill['id']}")
        if not _skill_matches(client, workspace_id, skill, directory):
            raise ReconcileError(f"published skill {name} does not match Git")
        skill_ids.append(str(skill["id"]))
    if len(skill_ids) != 7:
        raise ReconcileError(f"expected seven managed skills, found {len(skill_ids)}")
    log("skills READY: 7 published and verified")
    return skill_ids


def _load_manifest(directory: Path, filename: str) -> tuple[dict[str, Any], str]:
    manifest = json.loads((directory / filename).read_text())
    prompt_file = manifest.get("prompt_file")
    if not isinstance(prompt_file, str) or not prompt_file:
        raise ReconcileError(f"{filename} is missing prompt_file")
    prompt_path = (directory / prompt_file).resolve()
    if prompt_path.parent != directory.resolve():
        raise ReconcileError(f"{filename} prompt must stay in {directory}")
    prompt = prompt_path.read_text().strip()
    if not prompt:
        raise ReconcileError(f"{filename} prompt is empty")
    return manifest, prompt


def _workspace_model(
    client: httpx.Client, workspace_id: str, provider: str, name: str
) -> dict[str, Any]:
    payload = request(client, "GET", f"/workspaces/{workspace_id}/agent-models")
    rows = tracecat.paginated_items(payload, "workspace model list")
    matches = [
        row
        for row in rows
        if row.get("model_provider") == provider and row.get("model_name") == name
    ]
    if len(matches) != 1:
        raise ReconcileError(
            f"grader model {provider}/{name} is not uniquely available"
        )
    return matches[0]


def _preset_payload(
    manifest: dict[str, Any], prompt: str, model: dict[str, Any], skill_ids: list[str]
) -> dict[str, Any]:
    fields = (
        "name",
        "slug",
        "description",
        "actions",
        "namespaces",
        "tool_approvals",
        "mcp_integrations",
        "agents",
        "retries",
        "enable_thinking",
        "enable_internet_access",
    )
    missing = [field for field in fields if field not in manifest]
    if missing:
        raise ReconcileError(f"preset manifest is missing fields: {missing}")
    return {field: manifest[field] for field in fields} | {
        "instructions": prompt,
        "model_name": model["model_name"],
        "model_provider": model["model_provider"],
        "catalog_id": model.get("catalog_id") or model.get("id"),
        "skills": [{"skill_id": skill_id} for skill_id in skill_ids],
    }


def reconcile_preset(
    client: httpx.Client, workspace_id: str, desired: dict[str, Any]
) -> dict[str, Any]:
    base = f"/workspaces/{workspace_id}/agent/presets"
    rows = request(client, "GET", base)
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and (row.get("slug") == desired["slug"] or row.get("name") == desired["name"])
    ]
    if len(matches) > 1:
        raise ReconcileError(f"multiple presets match {desired['slug']}")
    if matches:
        preset_id = str(matches[0]["id"])
        request(client, "PATCH", f"{base}/{preset_id}", body=desired)
    else:
        created = request(client, "POST", base, body=desired, expected=(201,))
        preset_id = str(created["id"])
    actual = request(client, "GET", f"{base}/{preset_id}")
    simple_fields = [key for key in desired if key != "skills"]
    drift = [key for key in simple_fields if actual.get(key) != desired[key]]
    actual_skill_ids = [
        str(row.get("skill_id"))
        for row in actual.get("skills", [])
        if isinstance(row, dict)
    ]
    desired_skill_ids = [str(row["skill_id"]) for row in desired["skills"]]
    if actual_skill_ids != desired_skill_ids:
        drift.append("skills")
    if drift:
        raise ReconcileError(f"preset {desired['slug']} drifted fields: {drift}")
    log(f"preset READY: {desired['slug']}")
    return actual


def reconcile_presets(
    client: httpx.Client, workspace_id: str, skill_ids: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    investigator_manifest, investigator_prompt = _load_manifest(
        AGENT_DIR, "investigator-preset.json"
    )
    if investigator_manifest.get("model_selection") != "organization_default":
        raise ReconcileError("investigator must use organization_default")
    try:
        investigator_model = tracecat.default_agent_model(client)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc
    investigator = reconcile_preset(
        client,
        workspace_id,
        _preset_payload(
            investigator_manifest, investigator_prompt, investigator_model, skill_ids
        ),
    )
    grader_manifest, grader_prompt = _load_manifest(EVALS_DIR, "grader-preset.json")
    grader_model = _workspace_model(
        client,
        workspace_id,
        str(grader_manifest["model_provider"]),
        str(grader_manifest["model_name"]),
    )
    grader = reconcile_preset(
        client,
        workspace_id,
        _preset_payload(grader_manifest, grader_prompt, grader_model, []),
    )
    if grader.get("actions") or grader.get("mcp_integrations") or grader.get("skills"):
        raise ReconcileError("grader must remain tool-free")
    return investigator, grader


def enrichment_status(client: httpx.Client, workspace_id: str) -> dict[str, bool]:
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
        workspace_id = login(client)
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
    client: httpx.Client | None = None,
    email: str | None = None,
    password: str | None = None,
) -> None:
    context = tracecat.client() if client is None else nullcontext(client)
    with context as client:
        request(client, "GET", "/health")
        workspace_id = login(client, email, password)
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
            if len(matches) != 1 or not _skill_matches(
                client, workspace_id, matches[0], directory
            ):
                raise ReconcileError(
                    f"managed skill {directory.name} is missing or drifted"
                )
            skill_ids.append(str(matches[0]["id"]))

        investigator_manifest, investigator_prompt = _load_manifest(
            AGENT_DIR, "investigator-preset.json"
        )
        try:
            investigator_model = tracecat.default_agent_model(client)
        except tracecat.TracecatError as exc:
            raise ReconcileError(str(exc)) from exc
        grader_manifest, grader_prompt = _load_manifest(EVALS_DIR, "grader-preset.json")
        grader_model = _workspace_model(
            client,
            workspace_id,
            str(grader_manifest["model_provider"]),
            str(grader_manifest["model_name"]),
        )
        desired_presets = (
            _preset_payload(
                investigator_manifest,
                investigator_prompt,
                investigator_model,
                skill_ids,
            ),
            _preset_payload(grader_manifest, grader_prompt, grader_model, []),
        )
        preset_rows = request(
            client, "GET", f"/workspaces/{workspace_id}/agent/presets"
        )
        if not isinstance(preset_rows, list):
            raise ReconcileError("preset list is malformed")
        for desired in desired_presets:
            matches = [
                row
                for row in preset_rows
                if isinstance(row, dict) and row.get("slug") == desired["slug"]
            ]
            if len(matches) != 1:
                raise ReconcileError(
                    f"preset {desired['slug']} is missing or ambiguous"
                )
            actual = request(
                client,
                "GET",
                f"/workspaces/{workspace_id}/agent/presets/{matches[0]['id']}",
            )
            drift = [
                key
                for key, value in desired.items()
                if key != "skills" and actual.get(key) != value
            ]
            actual_skill_ids = [
                str(row.get("skill_id"))
                for row in actual.get("skills", [])
                if isinstance(row, dict)
            ]
            if actual_skill_ids != [str(row["skill_id"]) for row in desired["skills"]]:
                drift.append("skills")
            if drift:
                raise ReconcileError(
                    f"preset {desired['slug']} drifted fields: {drift}"
                )
        enrichments = enrichment_status(client, workspace_id)
    print(
        f"cases={len(cases)}/34 investigated={investigated} skills={len(skill_ids)}/7 "
        "investigator=ready grader=ready "
        f"urlscan={'configured' if enrichments['urlscan'] else 'pending'} "
        f"virustotal={'configured' if enrichments['virustotal'] else 'pending'}"
    )


def reset_managed_evaluations() -> None:
    with tracecat.client() as client:
        request(client, "GET", "/health")
        workspace_id = login(client)
        cases = list_managed_cases(client, workspace_id)
        expected = {str(row["payload"]["alert_id"]) for row in source_cases()}
        if set(cases) != expected:
            raise ReconcileError(
                "managed cases are ambiguous; refusing destructive cleanup"
            )
        for alert_id, case in cases.items():
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
                expected=(204,),
            )
            log(f"removed managed evaluation state for {alert_id}")
        reconcile_cases(client, workspace_id)
    log(
        "managed cases and case-scoped investigations were reset; providers, integrations, skills, and presets were retained"
    )
