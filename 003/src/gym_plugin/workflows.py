"""Reconcile Gym 003's managed Tracecat workflows.

The checked-in JSON files use Tracecat's external workflow definition format.  The
reconciler imports them with stable UUIDs, assigns stable aliases, publishes them,
and refuses to silently overwrite a workflow whose graph has drifted.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from gymctl.http import ClientLike


WORKFLOW_DIR = Path(__file__).resolve().parents[2] / "benchmark/workflows"


class WorkflowError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkflowSpec:
    filename: str
    alias: str


WORKFLOW_SPECS = (
    WorkflowSpec("verification.json", "gym-003-verification"),
    WorkflowSpec("scan.json", "gym-003-scan"),
    WorkflowSpec("rule-application.json", "gym-003-rule-application"),
)

# Keep the retired identity here after removing its import fixture. A title alone
# is not proof of ownership: users can create workflows with the same title.
RETIRED_INVESTIGATION_ID = "00000000-0000-4000-8000-000000000303"
RETIRED_INVESTIGATION_ALIAS = "gym-003-investigation"
RETIRED_INVESTIGATION_TITLE = "Gym 003 - Investigate exploitability"


def _retired_candidates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row for row in rows
        if row.get("id") == RETIRED_INVESTIGATION_ID
        or row.get("alias") == RETIRED_INVESTIGATION_ALIAS
        or row.get("title") == RETIRED_INVESTIGATION_TITLE
    ]


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
        stable_id = row.get("id") == RETIRED_INVESTIGATION_ID
        named_identity = (
            row.get("alias") == RETIRED_INVESTIGATION_ALIAS
            and row.get("title") == RETIRED_INVESTIGATION_TITLE
        )
        if not row.get("id") or not (stable_id or named_identity):
            raise WorkflowError(
                "retired investigation workflow identity is ambiguous; "
                "refusing to delete it"
            )
    for row in candidates:
        request(client, "DELETE", f"{base}/{row['id']}", expected=(204,))
        if logger:
            logger(f"workflow RETIRED: {RETIRED_INVESTIGATION_ALIAS}")
    if candidates:
        rows = _rows(request(client, "GET", base, params={"limit": 0}))
        if _retired_candidates(rows):
            raise WorkflowError("retired investigation workflow remains after deletion")
    return rows


def load_definition(spec: WorkflowSpec) -> dict[str, Any]:
    path = WORKFLOW_DIR / spec.filename
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


def _persisted_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Return authored fields that Tracecat persists in committed DSL content."""

    value = copy.deepcopy(definition)
    entrypoint = value.get("entrypoint")
    if isinstance(entrypoint, dict):
        # Tracecat uses this ref while importing the draft graph, then stores the
        # trigger schema without it in the committed definition.
        entrypoint.pop("ref", None)
    return value


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
            f"Tracecat workflow import for {spec.alias} returned "
            f"{response.status_code}: {detail}"
        )
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
        raise WorkflowError(f"Tracecat workflow import for {spec.alias} is malformed")
    return payload


def reconcile_workflows(
    client: ClientLike,
    workspace_id: str,
    request: Callable[..., Any],
    *,
    logger: Callable[[str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Retire the wrapper, then reconcile the three managed workflows."""

    base = f"/workspaces/{workspace_id}/workflows"
    existing = _rows(request(client, "GET", base, params={"limit": 0}))
    existing = _retire_investigation(client, base, existing, request, logger)
    managed: dict[str, dict[str, Any]] = {}
    for spec in WORKFLOW_SPECS:
        document = load_definition(spec)
        title = str(document["definition"]["title"])
        matches = [
            row
            for row in existing
            if row.get("alias") == spec.alias or row.get("title") == title
        ]
        if len(matches) > 1:
            raise WorkflowError(f"multiple workflows match managed alias {spec.alias}")
        if matches:
            workflow = matches[0]
            remote = request(client, "GET", f"{base}/{workflow['id']}/definition")
            if not isinstance(remote, dict) or not _is_subset(
                _persisted_definition(document["definition"]), remote.get("content")
            ):
                raise WorkflowError(
                    f"managed workflow {spec.alias} has drifted; refusing to overwrite it"
                )
        else:
            workflow = _upload(client, workspace_id, spec, document)
            existing.append(workflow)

        workflow_id = str(workflow["id"])
        needs_publish = not workflow.get("version")
        if workflow.get("alias") != spec.alias or workflow.get("status") != "online":
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
                    f"could not publish managed workflow {spec.alias}: {commit!r}"
                )
        current = request(client, "GET", f"{base}/{workflow_id}")
        if (
            not isinstance(current, dict)
            or current.get("alias") != spec.alias
            or current.get("status") != "online"
        ):
            raise WorkflowError(f"managed workflow {spec.alias} was not activated")
        managed[spec.alias] = current
        if logger:
            logger(f"workflow READY: {spec.alias}")
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
        matches = [row for row in existing if row.get("alias") == spec.alias]
        if len(matches) != 1:
            raise WorkflowError(
                f"managed workflow {spec.alias} is missing or ambiguous ({len(matches)})"
            )
        workflow = matches[0]
        if workflow.get("status") != "online" or not workflow.get("version"):
            raise WorkflowError(
                f"managed workflow {spec.alias} is not published online"
            )
        remote = request(client, "GET", f"{base}/{workflow['id']}/definition")
        if not isinstance(remote, dict) or not _is_subset(
            _persisted_definition(document["definition"]), remote.get("content")
        ):
            raise WorkflowError(f"managed workflow {spec.alias} has drifted")
        result[spec.alias] = workflow
    return result
