"""Reconcile the supplier intake vulnerability case and its managed resources."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from gymctl import presets, tracecat
from gymctl.http import ClientLike

from . import workflows


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2]))
AGENT_DIR = ROOT / "benchmark/agent"
SKILLS_DIR = AGENT_DIR / "skills"
SCENARIO = "supplier-intake"
ASSET = "supplier.intake.test"
CVE = "CVE-2026-21858"
DEDUP_KEY = f"{SCENARIO}|{ASSET}|{CVE}"
ANALYST_SLUG = "analyst"
RETIRED_PRESET_SLUGS = {
    "gym-003-attack-surface",
    "gym-003-mitigation-analyst",
}
MANAGED_PRESET_SLUGS = {ANALYST_SLUG, *RETIRED_PRESET_SLUGS}
LEGACY_COMMENT_HEADINGS = (
    "## Gym 003 verification",
    "## Sanitized Gym 003 mitigation proposal",
    "## Gym 003 firewall task result",
)
LEGACY_SESSION_TITLES = {
    "Verify supplier-intake case verdict",
    "Review supplier intake mitigation proposal",
}
SECRET_NAME = "gym_003_test_api"
SECRET_KEY = "TOKEN"
DISPLAY_NAMES = {
    "gym-003-verification": "exploitability verification",
    "gym-003-scan": "supplier intake scan",
    "gym-003-rule-application": "reviewed firewall change",
    "gym-003-investigation": "previous investigation wrapper",
    "gym-003-attack-surface": "previous verification specialist",
    "gym-003-mitigation-analyst": "previous mitigation specialist",
}
CASE_DESCRIPTION = """## Executive summary

Nuclei identified an n8n version associated with `CVE-2026-21858` on the supplier intake service. This is a high-confidence lead that requires active validation before impact or containment is claimed.

## Initial evidence

| Signal | Observed | Decision |
| --- | --- | --- |
| Asset | Supplier intake service | Validate only through the exposed ingress |
| Finding | Vulnerable-version match | Confirm impact independently |
| Required traffic | Upload, webhook, login, health | Preserve every path after mitigation |

## Affected service

The exposed route accepts supplier submissions and supports production business traffic. Validation must remain bounded to that ingress and retain only sanitized evidence.

## Investigation plan

```mermaid
flowchart LR
    A["Scanner signal"] --> B["Analyst<br/>confirm impact"]
    B --> C["Analyst<br/>propose control"]
    C --> D["Human review<br/>apply rule"]
    D --> E["Retest<br/>attack denied<br/>required traffic passes"]
```

## Decision boundary

A successful result demonstrates mitigation at the tested ingress. It does not patch the vulnerable application, which still requires remediation.
"""


class ReconcileError(RuntimeError):
    pass


def log(message: str) -> None:
    for internal_name, display_name in DISPLAY_NAMES.items():
        message = message.replace(internal_name, display_name)
    print(f"[supplier-intake] {message}", flush=True)


def request(
    client: ClientLike,
    method: str,
    url: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    try:
        return tracecat.request_json(client, method, url, expected=expected, **kwargs)
    except tracecat.TracecatError as exc:
        raise ReconcileError(str(exc)) from exc


def desired_case() -> dict[str, Any]:
    return {
        "summary": "Suspected unauthenticated n8n RCE on supplier intake",
        "description": CASE_DESCRIPTION,
        "status": "new",
        "priority": "high",
        "severity": "critical",
        "payload": {
            "gym_id": "003",
            "dedup_key": DEDUP_KEY,
            "scenario": SCENARIO,
            "asset": ASSET,
            "cve": CVE,
            "scanner_assessment": "suspected_vulnerable_version",
            "proposal_revision": 1,
            "evidence": [],
        },
    }


def list_managed_cases(client: ClientLike, workspace_id: str) -> list[dict[str, Any]]:
    payload = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/cases",
        params={"limit": 100, "include_payload": "true"},
    )
    rows = tracecat.paginated_items(payload, "managed case list")
    return [
        row
        for row in rows
        if isinstance(row.get("payload"), dict)
        and row["payload"].get("gym_id") == "003"
    ]


def reconcile_case(
    client: ClientLike, workspace_id: str, *, create_missing: bool = True
) -> dict[str, Any]:
    managed = list_managed_cases(client, workspace_id)
    matches = [
        row for row in managed if row.get("payload", {}).get("dedup_key") == DEDUP_KEY
    ]
    if len(matches) > 1:
        raise ReconcileError(f"duplicate managed cases for {DEDUP_KEY}")
    unknown = [
        row.get("payload", {}).get("dedup_key")
        for row in managed
        if row.get("payload", {}).get("dedup_key") != DEDUP_KEY
    ]
    if unknown:
        raise ReconcileError(f"unexpected managed cases require review: {unknown}")
    if not matches:
        if not create_missing:
            raise ReconcileError(f"managed case {DEDUP_KEY} is missing")
        request(
            client,
            "POST",
            f"/workspaces/{workspace_id}/cases",
            body=desired_case(),
            expected=(201,),
        )
        log(f"created case {DEDUP_KEY}")
        matches = [
            row
            for row in list_managed_cases(client, workspace_id)
            if row.get("payload", {}).get("dedup_key") == DEDUP_KEY
        ]
        if len(matches) != 1:
            raise ReconcileError("managed case was not uniquely visible after creation")

    case = matches[0]
    actual = request(client, "GET", f"/workspaces/{workspace_id}/cases/{case['id']}")
    if not isinstance(actual, dict):
        raise ReconcileError("Tracecat case response is malformed")
    payload = actual.get("payload")
    immutable = {
        "gym_id": "003",
        "dedup_key": DEDUP_KEY,
        "scenario": SCENARIO,
        "asset": ASSET,
        "cve": CVE,
    }
    if not isinstance(payload, dict) or any(
        payload.get(k) != v for k, v in immutable.items()
    ):
        raise ReconcileError("managed case identity fields have drifted")

    desired = desired_case()
    content_patch = {
        field: desired[field]
        for field in ("summary", "description")
        if actual.get(field) != desired[field]
    }
    if content_patch:
        request(
            client,
            "PATCH",
            f"/workspaces/{workspace_id}/cases/{case['id']}",
            body=content_patch,
            expected=(204,),
        )
        log(f"updated case presentation {DEDUP_KEY}")
        actual = {**actual, **content_patch}
    return actual


def append_case_evidence(
    client: ClientLike,
    workspace_id: str,
    case_id: str,
    evidence: dict[str, Any],
) -> bool:
    """Append one evidence record by content hash without duplicating scan retries."""

    actual = request(client, "GET", f"/workspaces/{workspace_id}/cases/{case_id}")
    if not isinstance(actual, dict) or not isinstance(actual.get("payload"), dict):
        raise ReconcileError("managed case response has no payload")
    payload = dict(actual["payload"])
    rows = list(payload.get("evidence") or [])

    def fingerprint(item: Any) -> str:
        raw = json.dumps(
            item, sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    digest = fingerprint(evidence)
    if any(fingerprint(row) == digest for row in rows):
        return False
    rows.append(evidence)
    payload["evidence"] = rows
    request(
        client,
        "PATCH",
        f"/workspaces/{workspace_id}/cases/{case_id}",
        body={"payload": payload},
        expected=(204,),
    )
    return True


def _legacy_case_artifact_ids(
    comments: Any, sessions: Any, case_id: str
) -> tuple[list[str], list[str]]:
    """Select only artifacts emitted by the retired two-agent implementation."""

    if not isinstance(comments, list) or not isinstance(sessions, list):
        raise ReconcileError("Tracecat returned malformed case artifacts")
    comment_ids = [
        str(row["id"])
        for row in comments
        if isinstance(row, dict)
        and row.get("id")
        and isinstance(row.get("content"), str)
        and row["content"].startswith(LEGACY_COMMENT_HEADINGS)
    ]
    session_ids = [
        str(row["id"])
        for row in sessions
        if isinstance(row, dict)
        and row.get("id")
        and row.get("title") in LEGACY_SESSION_TITLES
        and row.get("entity_type") == "case"
        and str(row.get("entity_id")) == case_id
    ]
    return comment_ids, session_ids


def retire_legacy_case_artifacts(
    client: ClientLike, workspace_id: str, case_id: str
) -> None:
    """Remove the known case output left by the retired specialist presets."""

    comments_base = f"/workspaces/{workspace_id}/cases/{case_id}/comments"
    sessions_base = f"/workspaces/{workspace_id}/agent/sessions"
    comments = request(client, "GET", comments_base)
    sessions = request(
        client,
        "GET",
        sessions_base,
        params={"entity_type": "case", "entity_id": case_id, "limit": 100},
    )
    comment_ids, session_ids = _legacy_case_artifact_ids(comments, sessions, case_id)
    for comment_id in comment_ids:
        request(
            client,
            "DELETE",
            f"{comments_base}/{comment_id}",
            expected=(204,),
        )
    for session_id in session_ids:
        request(
            client,
            "DELETE",
            f"{sessions_base}/{session_id}",
            expected=(204,),
        )
    if comment_ids or session_ids:
        log(
            f"retired {len(comment_ids)} legacy comments and "
            f"{len(session_ids)} legacy agent sessions"
        )


def verify_no_legacy_case_artifacts(
    client: ClientLike, workspace_id: str, case_id: str
) -> None:
    comments = request(
        client, "GET", f"/workspaces/{workspace_id}/cases/{case_id}/comments"
    )
    sessions = request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/agent/sessions",
        params={"entity_type": "case", "entity_id": case_id, "limit": 100},
    )
    comment_ids, session_ids = _legacy_case_artifact_ids(comments, sessions, case_id)
    if comment_ids or session_ids:
        raise ReconcileError("retired case artifacts remain; run reconcile")


def _task_definitions(
    case_id: str, managed_workflows: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], ...]:
    common = {"case_id": case_id, "scenario": SCENARIO, "proposal_revision": 1}
    rule_workflow = str(managed_workflows["gym-003-rule-application"]["id"])
    verify_workflow = str(managed_workflows["gym-003-verification"]["id"])
    return (
        {
            "title": "Create BLOCK rule",
            "description": "Apply the current reviewed proposal in BLOCK mode and verify attack denial plus benign compatibility.",
            "priority": "critical",
            "workflow_id": rule_workflow,
            "default_trigger_values": common | {"mode": "BLOCK"},
        },
        {
            "title": "Create LOG-only rule",
            "description": "Apply the current predicate in nonblocking LOG_ONLY mode, verify exploitability, and collect matching events.",
            "priority": "high",
            "workflow_id": rule_workflow,
            "default_trigger_values": common | {"mode": "LOG_ONLY"},
        },
        {
            "title": "Test exploitability",
            "description": "Run a fresh attack and benign verification against current protection without changing WAF configuration.",
            "priority": "high",
            "workflow_id": verify_workflow,
            "default_trigger_values": common | {"mode": "VERIFY_ONLY"},
        },
    )


def reconcile_tasks(
    client: ClientLike,
    workspace_id: str,
    case_id: str,
    managed_workflows: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    base = f"/workspaces/{workspace_id}/cases/{case_id}/tasks"
    rows = request(client, "GET", base)
    if not isinstance(rows, list):
        raise ReconcileError("Tracecat case task list response is malformed")
    desired = _task_definitions(case_id, managed_workflows)
    managed_titles = {item["title"] for item in desired}
    final: list[dict[str, Any]] = []
    for item in desired:
        matches = [
            row
            for row in rows
            if isinstance(row, dict) and row.get("title") == item["title"]
        ]
        if len(matches) > 1:
            raise ReconcileError(f"duplicate case tasks named {item['title']!r}")
        if not matches:
            task = request(client, "POST", base, body=item, expected=(201,))
            log(f"created case task {item['title']}")
        else:
            task = matches[0]
            drift = {
                key: value for key, value in item.items() if task.get(key) != value
            }
            if drift:
                task = request(
                    client,
                    "PATCH",
                    f"{base}/{task['id']}",
                    body=drift,
                )
                log(f"repaired case task {item['title']}")
        if not isinstance(task, dict):
            raise ReconcileError(
                f"Tracecat case task {item['title']!r} response is malformed"
            )
        final.append(task)
    duplicates = [
        title
        for title in managed_titles
        if sum(1 for row in rows if isinstance(row, dict) and row.get("title") == title)
        > 1
    ]
    if duplicates:
        raise ReconcileError(f"managed task duplicates remain: {duplicates}")
    return final


def reconcile_test_api_secret(client: ClientLike, workspace_id: str) -> None:
    token = os.environ.get("GYM_TEST_API_TOKEN")
    if not token:
        raise ReconcileError(
            "required environment variable is missing: GYM_TEST_API_TOKEN"
        )
    base = f"/workspaces/{workspace_id}/secrets"
    rows = request(client, "GET", base)
    if not isinstance(rows, list):
        raise ReconcileError("Tracecat secret inventory response is malformed")
    matches = [
        row for row in rows if isinstance(row, dict) and row.get("name") == SECRET_NAME
    ]
    if len(matches) > 1:
        raise ReconcileError(f"multiple workspace secrets match {SECRET_NAME}")
    body = {
        "type": "custom",
        "name": SECRET_NAME,
        "description": "Credential used by controlled supplier intake verification jobs.",
        "keys": [{"key": SECRET_KEY, "value": token}],
        "environment": "default",
    }
    if matches:
        request(
            client, "POST", f"{base}/{matches[0]['id']}", body=body, expected=(204,)
        )
    else:
        request(client, "POST", base, body=body, expected=(201,))
    verify_test_api_secret(client, workspace_id)
    log("verification credential READY")


def verify_test_api_secret(client: ClientLike, workspace_id: str) -> None:
    rows = request(client, "GET", f"/workspaces/{workspace_id}/secrets")
    if not isinstance(rows, list):
        raise ReconcileError("Tracecat secret inventory response is malformed")
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("name") == SECRET_NAME
        and set(row.get("keys") or []) == {SECRET_KEY}
        and row.get("environment") == "default"
    ]
    if len(matches) != 1:
        raise ReconcileError(f"managed secret {SECRET_NAME} is missing or drifted")


def reconcile_skills(client: ClientLike, workspace_id: str) -> list[str]:
    try:
        skill_ids = presets.reconcile_skills(
            client,
            workspace_id,
            SKILLS_DIR,
            managed_preset_slugs=MANAGED_PRESET_SLUGS,
            expected_count=2,
            logger=log,
        )
    except presets.PresetError as exc:
        raise ReconcileError(str(exc)) from exc
    log("skills READY: two published and verified")
    return skill_ids


def verify_skills(client: ClientLike, workspace_id: str) -> list[str]:
    directories = sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir())
    if len(directories) != 2:
        raise ReconcileError(
            f"expected two local skills, found {len(directories)}"
        )
    rows = tracecat.paginated_items(
        request(
            client,
            "GET",
            f"/workspaces/{workspace_id}/agent/skills",
            params={"limit": 100},
        ),
        "skill list",
    )
    skill_ids: list[str] = []
    for directory in directories:
        matches = [
            row
            for row in rows
            if row.get("name") == directory.name
            or row.get("slug") == directory.name
        ]
        try:
            matches_source = len(matches) == 1 and presets.skill_matches(
                client, workspace_id, matches[0], directory
            )
        except presets.PresetError as exc:
            raise ReconcileError(str(exc)) from exc
        if not matches_source:
            raise ReconcileError(
                f"published skill {directory.name} is missing or drifted"
            )
        skill_ids.append(str(matches[0]["id"]))
    return skill_ids


def desired_preset(client: ClientLike, skill_ids: list[str]) -> dict[str, Any]:
    filename = "analyst-preset.json"
    try:
        manifest, prompt = presets.load_manifest(AGENT_DIR, filename)
        model = tracecat.default_agent_model(client)
    except (presets.PresetError, tracecat.TracecatError) as exc:
        raise ReconcileError(str(exc)) from exc
    if manifest.get("model_selection") != "organization_default":
        raise ReconcileError(f"{filename} must use organization_default")
    payload = presets.preset_payload(manifest, prompt, model, skill_ids)
    if "output_type" in manifest:
        payload["output_type"] = manifest["output_type"]
    return payload


def _preset_rows(client: ClientLike, workspace_id: str) -> list[dict[str, Any]]:
    rows = request(client, "GET", f"/workspaces/{workspace_id}/agent/presets")
    if not isinstance(rows, list):
        raise ReconcileError("Tracecat preset list response is malformed")
    return [row for row in rows if isinstance(row, dict)]


def _validate_managed_preset_inventory(rows: list[dict[str, Any]]) -> None:
    unexpected = [
        {"id": row.get("id"), "name": row.get("name"), "slug": row.get("slug")}
        for row in rows
        if row.get("slug") not in MANAGED_PRESET_SLUGS
    ]
    if unexpected:
        raise ReconcileError(
            f"unexpected agent presets require review: {unexpected}"
        )
    missing_ids = [row.get("slug") for row in rows if not row.get("id")]
    if missing_ids:
        raise ReconcileError(f"agent presets are missing IDs: {missing_ids}")


def _verify_exact_preset_inventory(
    rows: list[dict[str, Any]], desired: dict[str, Any]
) -> None:
    if len(rows) != 1:
        raise ReconcileError(
            f"expected exactly one visible Analyst preset, found {len(rows)}"
        )
    actual = rows[0]
    if actual.get("slug") != desired["slug"] or actual.get("name") != desired["name"]:
        raise ReconcileError("the sole visible preset is not Analyst")


def reconcile_presets(
    client: ClientLike, workspace_id: str, skill_ids: list[str]
) -> dict[str, Any]:
    desired = desired_preset(client, skill_ids)
    rows = _preset_rows(client, workspace_id)
    _validate_managed_preset_inventory(rows)
    try:
        actual = presets.reconcile_preset(client, workspace_id, desired)
    except presets.PresetError as exc:
        raise ReconcileError(str(exc)) from exc

    rows = _preset_rows(client, workspace_id)
    retired = [row for row in rows if row.get("slug") in RETIRED_PRESET_SLUGS]
    for row in retired:
        request(
            client,
            "DELETE",
            f"/workspaces/{workspace_id}/agent/presets/{row['id']}",
            expected=(204,),
        )
        log(f"preset RETIRED: {row['slug']}")

    rows = _preset_rows(client, workspace_id)
    _verify_exact_preset_inventory(rows, desired)
    try:
        actual = presets.verify_preset(client, workspace_id, desired)
    except presets.PresetError as exc:
        raise ReconcileError(str(exc)) from exc
    log(f"preset READY: {desired['slug']}")
    return actual


def reconcile() -> None:
    with tracecat.client() as client:
        request(client, "GET", "/health")
        workspace_id = tracecat.login(client)
        try:
            tracecat.verify_entitlements(client)
        except tracecat.TracecatError as exc:
            raise ReconcileError(str(exc)) from exc
        reconcile_test_api_secret(client, workspace_id)
        try:
            managed_workflows = workflows.reconcile_workflows(
                client, workspace_id, request, logger=log
            )
        except workflows.WorkflowError as exc:
            raise ReconcileError(str(exc)) from exc
        case = reconcile_case(client, workspace_id)
        retire_legacy_case_artifacts(client, workspace_id, str(case["id"]))
        reconcile_tasks(client, workspace_id, str(case["id"]), managed_workflows)
        skill_ids = reconcile_skills(client, workspace_id)
        reconcile_presets(client, workspace_id, skill_ids)
    log(
        "READY: case, three workflow-backed tasks, three workflows, "
        "two skills, and one Analyst preset"
    )


def status(
    client: ClientLike | None = None,
    email: str | None = None,
    password: str | None = None,
) -> None:
    context = tracecat.client() if client is None else nullcontext(client)
    with context as active:
        request(active, "GET", "/health")
        workspace_id = tracecat.login(active, email, password)
        try:
            tracecat.verify_entitlements(active)
            verify_test_api_secret(active, workspace_id)
            managed_workflows = workflows.verify_workflows(
                active, workspace_id, request
            )
        except (tracecat.TracecatError, workflows.WorkflowError) as exc:
            raise ReconcileError(str(exc)) from exc
        case = reconcile_case(active, workspace_id, create_missing=False)
        verify_no_legacy_case_artifacts(active, workspace_id, str(case["id"]))
        expected = _task_definitions(str(case["id"]), managed_workflows)
        rows = request(
            active,
            "GET",
            f"/workspaces/{workspace_id}/cases/{case['id']}/tasks",
        )
        if not isinstance(rows, list):
            raise ReconcileError("Tracecat case task list response is malformed")
        for item in expected:
            matches = [
                row
                for row in rows
                if isinstance(row, dict) and row.get("title") == item["title"]
            ]
            if len(matches) != 1 or any(
                matches[0].get(key) != value for key, value in item.items()
            ):
                raise ReconcileError(
                    f"managed case task {item['title']!r} is missing or drifted"
                )
        skill_ids = verify_skills(active, workspace_id)
        desired = desired_preset(active, skill_ids)
        rows = _preset_rows(active, workspace_id)
        _validate_managed_preset_inventory(rows)
        _verify_exact_preset_inventory(rows, desired)
        try:
            presets.verify_preset(active, workspace_id, desired)
        except presets.PresetError as exc:
            raise ReconcileError(str(exc)) from exc
    log("READY: managed Tracecat state is exact")
