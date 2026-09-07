"""Reconcile Gym 003's managed Tracecat workflows.

The checked-in JSON files use Tracecat's external workflow definition format. The
reconciler imports the automatic scanner-intake and human-launched firewall
workflows with stable UUIDs, publishes them, and refuses to silently overwrite a
workflow whose graph has drifted.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from gymctl.http import ClientLike


WORKFLOW_DIR = Path(__file__).resolve().parents[2] / "benchmark/workflows"
LEGACY_WORKFLOW_DIR = WORKFLOW_DIR / "legacy"


class WorkflowError(RuntimeError):
    pass


_BASE62_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _canonical_workflow_id(value: Any) -> str | None:
    """Normalize Tracecat UUID, short, and legacy workflow identifiers."""

    if not isinstance(value, str) or not value:
        return None
    try:
        if value.startswith("wf_"):
            number = 0
            for character in value[3:]:
                number = number * 62 + _BASE62_CHARS.index(character)
            return str(UUID(int=number))
        if value.startswith("wf-") and len(value) == 35:
            return str(UUID(hex=value[3:]))
        return str(UUID(value))
    except (ValueError, IndexError):
        return None


@dataclass(frozen=True)
class WorkflowSpec:
    filename: str
    key: str
    alias: str | None


WORKFLOW_SPECS = (
    WorkflowSpec(
        "scanner-intake.json", "gym-003-scanner-intake", "scanner-intake"
    ),
    WorkflowSpec("rule-application.json", "gym-003-rule-application", None),
)

SCANNER_WEBHOOK_DESIRED = {
    "status": "online",
    "methods": ["POST"],
    "allowlisted_cidrs": [],
    "include_headers": False,
}

# Keep retired identities after removing their import fixtures. A title alone is
# not proof of ownership: stable IDs, or alias and title together, establish it.
RETIRED_WORKFLOWS = (
    (
        "00000000-0000-4000-8000-000000000301",
        "gym-003-verification",
        "Verify exploitability",
    ),
    (
        "00000000-0000-4000-8000-000000000302",
        None,
        "Scan supplier intake",
    ),
    (
        "00000000-0000-4000-8000-000000000303",
        "gym-003-investigation",
        "Gym 003 - Investigate exploitability",
    ),
)


def _retired_candidates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        for stable_id, alias, title in RETIRED_WORKFLOWS:
            if _canonical_workflow_id(row.get("id")) == stable_id or (
                alias is not None
                and row.get("alias") == alias
                and row.get("title") == title
            ):
                candidates.append(row)
                break
    return candidates


def _retire_investigation(
    client: ClientLike,
    base: str,
    rows: list[dict[str, Any]],
    request: Callable[..., Any],
    logger: Callable[[str], None] | None,
) -> list[dict[str, Any]]:
    candidates = _retired_candidates(rows)
    # Validate all candidates before deleting any: a partial migration should not
    # silently dispose of an unrelated workflow that only shares the title.
    for row in candidates:
        identities = [
            (_canonical_workflow_id(row.get("id")) == stable_id)
            or (
                alias is not None
                and row.get("alias") == alias
                and row.get("title") == title
            )
            for stable_id, alias, title in RETIRED_WORKFLOWS
        ]
        if not row.get("id") or not any(identities):
            raise WorkflowError(
                "retired investigation workflow identity is ambiguous; "
                "refusing to delete it"
            )
    for row in candidates:
        request(client, "DELETE", f"{base}/{row['id']}", expected=(204,))
        if logger:
            logger(f"workflow RETIRED: {row.get('alias') or row.get('title')}")
    if candidates:
        rows = _rows(request(client, "GET", base, params={"limit": 0}))
        if _retired_candidates(rows):
            raise WorkflowError("retired investigation workflow remains after deletion")
    return rows


def load_definition(spec: WorkflowSpec) -> dict[str, Any]:
    return _load_definition(WORKFLOW_DIR / spec.filename)


def load_legacy_definition(spec: WorkflowSpec) -> dict[str, Any]:
    """Load the one previously shipped definition eligible for migration."""

    return _load_definition(LEGACY_WORKFLOW_DIR / spec.filename)


def load_legacy_definitions(spec: WorkflowSpec) -> list[dict[str, Any]]:
    """Load every exact prior definition eligible for a managed migration."""

    path = Path(spec.filename)
    candidates = sorted(LEGACY_WORKFLOW_DIR.glob(f"{path.stem}*.json"))
    return [_load_definition(candidate) for candidate in candidates]


def _load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot load managed workflow {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("definition"), dict):
        raise WorkflowError(f"managed workflow {path} is not an external definition")
    workflow_id = value.get("workflow_id")
    if not isinstance(workflow_id, str) or not workflow_id:
        raise WorkflowError(f"managed workflow {path} has no stable workflow_id")
    definition = value["definition"]
    for field in ("title", "description", "entrypoint", "actions"):
        if field not in definition:
            raise WorkflowError(f"managed workflow {path} is missing {field}")
    return value


def _matches_definition(document: dict[str, Any], remote: Any) -> bool:
    """Match every authored field while allowing Tracecat-owned defaults."""

    return isinstance(remote, dict) and _is_subset(
        _persisted_definition(document["definition"]), remote.get("content")
    )


def _replace_known_legacy_workflow(
    client: ClientLike,
    workspace_id: str,
    base: str,
    spec: WorkflowSpec,
    workflow: dict[str, Any],
    remote: Any,
    request: Callable[..., Any],
    logger: Callable[[str], None] | None,
) -> dict[str, Any]:
    """Replace an exact prior managed definition and reject every other drift.

    Tracecat does not expose a public endpoint that atomically replaces a
    committed workflow definition. Deleting and re-importing the stable UUID is
    therefore limited to the complete authored definition shipped immediately
    before this release. Case-task foreign keys are repaired later in the same
    reconciliation pass.
    """

    legacy = next(
        (
            candidate
            for candidate in load_legacy_definitions(spec)
            if _matches_definition(candidate, remote)
        ),
        None,
    )
    if legacy is None:
        raise WorkflowError(
            f"managed workflow {spec.key} has drifted; refusing to overwrite it"
        )
    expected_id = str(legacy["workflow_id"])
    workflow_id = str(workflow.get("id", ""))
    if _canonical_workflow_id(workflow_id) != expected_id:
        raise WorkflowError(
            f"managed workflow {spec.key} has an unexpected identity; "
            "refusing to replace it"
        )
    request(client, "DELETE", f"{base}/{workflow_id}", expected=(204,))
    replacement = _upload(client, workspace_id, spec, load_definition(spec))
    if _canonical_workflow_id(replacement.get("id")) != expected_id:
        raise WorkflowError(
            f"managed workflow {spec.key} replacement did not retain its stable ID"
        )
    if logger:
        logger(f"workflow MIGRATED: {spec.key}")
    return replacement


def _persisted_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Return authored fields that Tracecat persists in committed DSL content."""

    value = copy.deepcopy(definition)
    entrypoint = value.get("entrypoint")
    if isinstance(entrypoint, dict):
        # Tracecat uses this ref while importing the draft graph, then stores the
        # trigger schema without it in the committed definition.
        entrypoint.pop("ref", None)
    return value


def _desired_layout(
    document: dict[str, Any],
) -> tuple[dict[str, float], dict[str, tuple[float, float]]]:
    """Return the checked-in trigger and action positions by action ref."""

    layout = document.get("layout")
    if not isinstance(layout, dict) or not isinstance(layout.get("trigger"), dict):
        raise WorkflowError("managed workflow has no trigger layout")
    trigger = layout["trigger"]
    if not isinstance(trigger.get("x"), (int, float)) or not isinstance(
        trigger.get("y"), (int, float)
    ):
        raise WorkflowError("managed workflow trigger layout is malformed")
    action_layout = layout.get("actions")
    if not isinstance(action_layout, list):
        raise WorkflowError("managed workflow action layout is malformed")
    positions: dict[str, tuple[float, float]] = {}
    for item in action_layout:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("ref"), str)
            or not isinstance(item.get("x"), (int, float))
            or not isinstance(item.get("y"), (int, float))
        ):
            raise WorkflowError("managed workflow action layout is malformed")
        positions[item["ref"]] = (float(item["x"]), float(item["y"]))
    expected_refs = {
        action["ref"]
        for action in document["definition"]["actions"]
        if isinstance(action, dict) and isinstance(action.get("ref"), str)
    }
    if set(positions) != expected_refs:
        raise WorkflowError("managed workflow layout does not cover every action")
    return {"x": float(trigger["x"]), "y": float(trigger["y"])}, positions


def _layout_matches(document: dict[str, Any], workflow: Any) -> bool:
    if not isinstance(workflow, dict) or not isinstance(workflow.get("actions"), dict):
        return False
    trigger, desired = _desired_layout(document)
    if (
        float(workflow.get("trigger_position_x", 0.0)) != trigger["x"]
        or float(workflow.get("trigger_position_y", 0.0)) != trigger["y"]
    ):
        return False
    actual = {
        action.get("ref"): (
            float(action.get("position_x", 0.0)),
            float(action.get("position_y", 0.0)),
        )
        for action in workflow["actions"].values()
        if isinstance(action, dict) and isinstance(action.get("ref"), str)
    }
    return actual == desired


def _reconcile_layout(
    client: ClientLike,
    workspace_id: str,
    workflow_id: str,
    document: dict[str, Any],
    workflow: Any,
    request: Callable[..., Any],
) -> dict[str, Any]:
    """Apply the authored graph layout through Tracecat's public layout API."""

    if not isinstance(workflow, dict) or not isinstance(workflow.get("actions"), dict):
        raise WorkflowError("managed workflow response has no action graph")
    if _layout_matches(document, workflow):
        return workflow
    trigger, desired = _desired_layout(document)
    actions_by_ref = {
        action.get("ref"): action
        for action in workflow["actions"].values()
        if isinstance(action, dict) and isinstance(action.get("ref"), str)
    }
    if set(actions_by_ref) != set(desired):
        raise WorkflowError("managed workflow action graph does not match its layout")
    request(
        client,
        "POST",
        f"/workspaces/{workspace_id}/actions/batch-positions",
        params={"workflow_id": workflow_id},
        body={
            "actions": [
                {
                    "action_id": actions_by_ref[ref]["id"],
                    "position": {"x": position[0], "y": position[1]},
                }
                for ref, position in desired.items()
            ],
            "trigger_position": trigger,
        },
        expected=(204,),
    )
    updated = request(
        client, "GET", f"/workspaces/{workspace_id}/workflows/{workflow_id}"
    )
    if not _layout_matches(document, updated):
        raise WorkflowError("managed workflow layout did not converge")
    return updated


def _reconcile_scanner_webhook(
    client: ClientLike,
    workspace_id: str,
    workflow_id: str,
    request: Callable[..., Any],
) -> dict[str, Any]:
    """Keep the scanner intake webhook published and attached to its action."""

    path = f"/workspaces/{workspace_id}/workflows/{workflow_id}/webhook"
    webhook = request(client, "GET", path)
    if not isinstance(webhook, dict):
        raise WorkflowError("scanner intake workflow has no webhook")
    if any(
        webhook.get(key) != value
        for key, value in SCANNER_WEBHOOK_DESIRED.items()
    ):
        request(
            client,
            "PATCH",
            path,
            body=SCANNER_WEBHOOK_DESIRED,
            expected=(204,),
        )
        webhook = request(client, "GET", path)
    if not isinstance(webhook, dict) or any(
        webhook.get(key) != value
        for key, value in SCANNER_WEBHOOK_DESIRED.items()
    ):
        raise WorkflowError("scanner intake webhook did not converge")
    if not isinstance(webhook.get("secret"), str) or not webhook["secret"]:
        raise WorkflowError("scanner intake webhook has no secret")
    return webhook


def _is_subset(desired: Any, actual: Any) -> bool:
    """Compare authored fields while allowing server-populated DSL defaults."""

    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(
            key in actual and _is_subset(value, actual[key])
            for key, value in desired.items()
        )
    if isinstance(desired, list):
        return (
            isinstance(actual, list)
            and len(desired) == len(actual)
            and all(
                _is_subset(left, right)
                for left, right in zip(desired, actual, strict=True)
            )
        )
    return desired == actual


def _rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise WorkflowError("Tracecat workflow list response is malformed")
    return [row for row in payload["items"] if isinstance(row, dict)]


def _upload(
    client: ClientLike,
    workspace_id: str,
    spec: WorkflowSpec,
    document: dict[str, Any],
) -> dict[str, Any]:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    response = client.request(
        "POST",
        f"/workspaces/{workspace_id}/workflows",
        data={"use_workflow_id": "true"},
        files={"file": (spec.filename, raw, "application/json")},
    )
    if response.status_code != 201:
        detail = response.text.strip().replace("\n", " ")[-600:]
        raise WorkflowError(
            f"Tracecat workflow import for {spec.key} returned "
            f"{response.status_code}: {detail}"
        )
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
        raise WorkflowError(f"Tracecat workflow import for {spec.key} is malformed")
    return payload


def reconcile_workflows(
    client: ClientLike,
    workspace_id: str,
    request: Callable[..., Any],
    *,
    logger: Callable[[str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Retire obsolete wrappers, then reconcile automatic and human workflows."""

    base = f"/workspaces/{workspace_id}/workflows"
    existing = _rows(request(client, "GET", base, params={"limit": 0}))
    existing = _retire_investigation(client, base, existing, request, logger)
    managed: dict[str, dict[str, Any]] = {}
    for spec in WORKFLOW_SPECS:
        document = load_definition(spec)
        title = str(document["definition"]["title"])
        stable_id = str(document["workflow_id"])
        matches = [
            row
            for row in existing
            if _canonical_workflow_id(row.get("id")) == stable_id
            or row.get("alias") == spec.key
            or row.get("title") == title
        ]
        if len(matches) > 1:
            raise WorkflowError(f"multiple workflows match managed identity {spec.key}")
        if matches:
            workflow = matches[0]
            remote = request(client, "GET", f"{base}/{workflow['id']}/definition")
            if not _matches_definition(document, remote):
                workflow = _replace_known_legacy_workflow(
                    client,
                    workspace_id,
                    base,
                    spec,
                    workflow,
                    remote,
                    request,
                    logger,
                )
                existing = [row for row in existing if row.get("id") != stable_id]
                existing.append(workflow)
        else:
            workflow = _upload(client, workspace_id, spec, document)
            existing.append(workflow)

        workflow_id = str(workflow["id"])
        alias_changed = workflow.get("alias") != spec.alias
        needs_publish = not workflow.get("version") or alias_changed
        if alias_changed or workflow.get("status") != "online":
            request(
                client,
                "PATCH",
                f"{base}/{workflow_id}",
                body={"alias": spec.alias, "status": "online"},
                expected=(204,),
            )
        if needs_publish:
            commit = request(client, "POST", f"{base}/{workflow_id}/commit")
            if not isinstance(commit, dict) or commit.get("status") != "success":
                raise WorkflowError(
                    f"could not publish managed workflow {spec.key}: {commit!r}"
                )
        current = request(client, "GET", f"{base}/{workflow_id}")
        if (
            not isinstance(current, dict)
            or current.get("alias") != spec.alias
            or current.get("status") != "online"
        ):
            raise WorkflowError(f"managed workflow {spec.key} was not activated")
        current = _reconcile_layout(
            client, workspace_id, workflow_id, document, current, request
        )
        if spec.key == "gym-003-scanner-intake":
            current["webhook"] = _reconcile_scanner_webhook(
                client, workspace_id, workflow_id, request
            )
        managed[spec.key] = current
        if logger:
            logger(f"workflow READY: {spec.key}")
    return managed


def verify_workflows(
    client: ClientLike,
    workspace_id: str,
    request: Callable[..., Any],
) -> dict[str, dict[str, Any]]:
    """Read-only exact authored-field and publication checks."""

    base = f"/workspaces/{workspace_id}/workflows"
    existing = _rows(request(client, "GET", base, params={"limit": 0}))
    if _retired_candidates(existing):
        raise WorkflowError("retired investigation workflow remains; run reconcile")
    result: dict[str, dict[str, Any]] = {}
    for spec in WORKFLOW_SPECS:
        document = load_definition(spec)
        stable_id = str(document["workflow_id"])
        if spec.alias is None and any(
            row.get("alias") == spec.key for row in existing
        ):
            raise WorkflowError(
                f"managed workflow {spec.key} still has an agent-callable alias"
            )
        matches = [
            row
            for row in existing
            if _canonical_workflow_id(row.get("id")) == stable_id
        ]
        if len(matches) != 1:
            raise WorkflowError(
                f"managed workflow {spec.key} is missing or ambiguous ({len(matches)})"
            )
        workflow = matches[0]
        if (
            workflow.get("status") != "online"
            or not workflow.get("version")
            or workflow.get("alias") != spec.alias
        ):
            raise WorkflowError(
                f"managed workflow {spec.key} is not published with its expected alias"
            )
        remote = request(client, "GET", f"{base}/{workflow['id']}/definition")
        if not _matches_definition(document, remote):
            raise WorkflowError(f"managed workflow {spec.key} has drifted")
        current = request(client, "GET", f"{base}/{workflow['id']}")
        if not _layout_matches(document, current):
            raise WorkflowError(f"managed workflow {spec.key} layout has drifted")
        if spec.key == "gym-003-scanner-intake":
            webhook = request(
                client,
                "GET",
                f"{base}/{workflow['id']}/webhook",
            )
            if not isinstance(webhook, dict) or any(
                webhook.get(key) != value
                for key, value in SCANNER_WEBHOOK_DESIRED.items()
            ):
                raise WorkflowError(
                    "scanner intake webhook is not online with its expected policy"
                )
            if not isinstance(webhook.get("secret"), str) or not webhook["secret"]:
                raise WorkflowError("scanner intake webhook has no secret")
            current["webhook"] = webhook
        result[spec.key] = current
    return result
