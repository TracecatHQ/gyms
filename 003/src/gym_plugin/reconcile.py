"""Reconcile Gym 003's case, tasks, workflows, secret, and agent presets."""

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
SCENARIO = "supplier-intake"
ASSET = "supplier.intake.test"
CVE = "CVE-2026-21858"
DEDUP_KEY = f"{SCENARIO}|{ASSET}|{CVE}"
ATTACK_SURFACE_SLUG = "gym-003-attack-surface"
MITIGATION_ANALYST_SLUG = "gym-003-mitigation-analyst"
SECRET_NAME = "gym_003_test_api"
SECRET_KEY = "TOKEN"
CASE_DESCRIPTION = """**Scanner finding:** Nuclei matched the vulnerable n8n version for `CVE-2026-21858`. Treat this as suspicion until the fixed-target verifier confirms impact.

| Signal | Observed | Decision |
| --- | --- | --- |
| Asset | `supplier.intake.test` | Test only through the WAF ingress |
| Scanner | Vulnerable-version match | Independent verification required |
| Compatibility | Upload, webhook, login, health | All paths must pass after mitigation |

```mermaid
flowchart LR
    A["Nuclei<br/>suspected"] --> B["Verifier<br/>confirm impact"]
    B --> C["Analyst<br/>propose policy"]
    C --> D["Human task<br/>apply rule"]
    D --> E["Retest<br/>attack denied<br/>benign passes"]
```

**Decision boundary:** a successful result means mitigation at this tested ingress; the application version remains vulnerable.
"""


class ReconcileError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gym-003] {message}", flush=True)


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
        "summary": f"Suspected unauthenticated n8n RCE at {ASSET}",
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
    rows = tracecat.paginated_items(payload, "Gym 003 case list")
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
        raise ReconcileError(f"unexpected Gym 003 cases require review: {unknown}")
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
        "description": "Managed Gym 003 fixed-target test API credential.",
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
    log(f"secret READY: {SECRET_NAME}")


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


def desired_presets(client: ClientLike) -> tuple[dict[str, Any], dict[str, Any]]:
    model = tracecat.default_agent_model(client)
    desired: list[dict[str, Any]] = []
    for filename in ("attack-surface-preset.json", "mitigation-analyst-preset.json"):
        manifest, prompt = presets.load_manifest(AGENT_DIR, filename)
        if manifest.get("model_selection") != "organization_default":
            raise ReconcileError(f"{filename} must use organization_default")
        payload = presets.preset_payload(manifest, prompt, model, [])
        if "output_type" in manifest:
            payload["output_type"] = manifest["output_type"]
        desired.append(payload)
    return desired[0], desired[1]


def reconcile_presets(
    client: ClientLike, workspace_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for desired in desired_presets(client):
        try:
            actual = presets.reconcile_preset(client, workspace_id, desired)
        except presets.PresetError as exc:
            raise ReconcileError(str(exc)) from exc
        result.append(actual)
        log(f"preset READY: {desired['slug']}")
    return result[0], result[1]


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
        reconcile_tasks(client, workspace_id, str(case["id"]), managed_workflows)
        reconcile_presets(client, workspace_id)
    log("READY: case, three workflow-backed tasks, three workflows, and two presets")


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
        for desired in desired_presets(active):
            try:
                presets.verify_preset(active, workspace_id, desired)
            except presets.PresetError as exc:
                raise ReconcileError(str(exc)) from exc
    log("READY: Gym 003 managed Tracecat state is exact")
