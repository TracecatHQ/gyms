"""Shared Tracecat workflow reconciliation for gym-managed automations."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import tracecat
from .http import ClientLike


class WorkflowError(RuntimeError):
    pass


def _request(
    client: ClientLike,
    method: str,
    path: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    try:
        return tracecat.request_json(client, method, path, expected=expected, **kwargs)
    except tracecat.TracecatError as exc:
        raise WorkflowError(str(exc)) from exc


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate one managed workflow definition."""
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot load workflow {path.name}: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or not set(manifest) <= {"alias", "definition", "layout", "case_trigger"}
        or not isinstance(manifest.get("alias"), str)
        or not manifest["alias"]
        or not isinstance(manifest.get("definition"), dict)
        or not manifest["definition"].get("title")
        or not isinstance(manifest["definition"].get("actions"), list)
    ):
        raise WorkflowError(f"workflow {path.name} has an invalid shape")
    return manifest


def _find_by_alias(
    client: ClientLike, workspace_id: str, alias: str
) -> dict[str, Any] | None:
    payload = _request(
        client, "GET", f"/workspaces/{workspace_id}/workflows", params={"limit": 0}
    )
    rows = tracecat.paginated_items(payload, "workflow list")
    matches = [row for row in rows if row.get("alias") == alias]
    if len(matches) > 1:
        raise WorkflowError(f"multiple workflows claim alias {alias!r}")
    return matches[0] if matches else None


def committed_definition(
    client: ClientLike, workspace_id: str, workflow_id: str
) -> dict[str, Any]:
    """Return the committed definition body for drift comparison."""
    export = _request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/workflows/{workflow_id}/export",
        params={"format": "json"},
    )
    if not isinstance(export, dict) or not isinstance(export.get("definition"), dict):
        raise WorkflowError("workflow export response is malformed")
    return export["definition"]


def definition_matches(
    client: ClientLike, workspace_id: str, workflow_id: str, manifest: dict[str, Any]
) -> bool:
    """Compare the committed definition to the managed one.

    Content comparison replaces a pinned version number: the workspace assigns
    version numbers on publish, so they differ between a fresh workspace and a
    long-lived one even when the definition is identical.
    """
    return _canonical(committed_definition(client, workspace_id, workflow_id)) == (
        _canonical(manifest["definition"])
    )


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def subflow_aliases(manifest: dict[str, Any]) -> set[str]:
    """Return the aliases this workflow invokes through ``core.workflow.execute``."""
    aliases: set[str] = set()
    for action in manifest["definition"].get("actions") or []:
        if not isinstance(action, dict):
            continue
        args = action.get("args")
        alias = args.get("workflow_alias") if isinstance(args, dict) else None
        if isinstance(alias, str) and alias:
            aliases.add(alias)
    return aliases


def publication_order(manifests: dict[str, dict[str, Any]]) -> list[str]:
    """Order aliases so every subflow is published before its caller.

    Committing a caller resolves the aliases it invokes, so a child that does
    not exist yet would fail the parent's commit. Filename order happens to work
    today but is not a dependency guarantee, so derive one from the definitions.
    """
    ordered: list[str] = []
    visiting: set[str] = set()

    def visit(alias: str, trail: tuple[str, ...]) -> None:
        if alias in ordered:
            return
        if alias in visiting:
            cycle = " -> ".join((*trail, alias))
            raise WorkflowError(f"managed workflows form a subflow cycle: {cycle}")
        visiting.add(alias)
        for child in sorted(subflow_aliases(manifests[alias])):
            if child in manifests:
                visit(child, (*trail, alias))
        visiting.discard(alias)
        ordered.append(alias)

    for alias in sorted(manifests):
        visit(alias, ())
    return ordered


def reconcile_workflows(
    client: ClientLike,
    workflows_dir: Path,
    workspace_id: str,
    *,
    expected_count: int,
    logger: Callable[[str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Publish every managed workflow, subflows before their callers."""
    paths = sorted(workflows_dir.glob("*.json"))
    if len(paths) != expected_count:
        raise WorkflowError(
            f"expected {expected_count} managed workflows, found {len(paths)}"
        )
    manifests: dict[str, dict[str, Any]] = {}
    for path in paths:
        manifest = load_manifest(path)
        alias = manifest["alias"]
        if alias in manifests:
            raise WorkflowError(f"duplicate managed workflow alias {alias!r}")
        manifest["_path"] = path
        manifests[alias] = manifest
    for alias, manifest in manifests.items():
        unknown = sorted(subflow_aliases(manifest) - set(manifests))
        if unknown:
            raise WorkflowError(
                f"workflow {alias} invokes unmanaged subflows: {unknown}"
            )
    published: dict[str, dict[str, Any]] = {}
    for alias in publication_order(manifests):
        manifest = manifests[alias]
        published[alias] = reconcile_workflow(
            client, workspace_id, manifest["_path"], logger=logger
        )
    return published


def reconcile_workflow(
    client: ClientLike,
    workspace_id: str,
    path: Path,
    *,
    logger: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish the managed workflow and return its workspace row.

    Imports the definition when the alias is absent, republishes when the
    committed definition has drifted, and always leaves exactly one committed
    version matching the file in Git.
    """
    manifest = load_manifest(path)
    alias = manifest["alias"]
    base = f"/workspaces/{workspace_id}/workflows"
    workflow = _find_by_alias(client, workspace_id, alias)

    if workflow is None:
        payload = json.dumps(
            {
                "definition": manifest["definition"],
                "layout": manifest.get("layout"),
                "case_trigger": manifest.get("case_trigger"),
            }
        ).encode()
        created = _request(
            client,
            "POST",
            base,
            expected=(200, 201),
            files={"file": (path.name, io.BytesIO(payload), "application/json")},
        )
        if not isinstance(created, dict) or not created.get("id"):
            raise WorkflowError(f"Tracecat did not return a workflow id for {alias}")
        workflow_id = str(created["id"])
        _request(
            client,
            "PATCH",
            f"{base}/{workflow_id}",
            body={"alias": alias},
            expected=(200, 204),
        )
        _request(client, "POST", f"{base}/{workflow_id}/commit", expected=(200, 201))
        if logger:
            logger(f"workflow imported and committed: {alias}")
        workflow = _find_by_alias(client, workspace_id, alias)
        if workflow is None:
            raise WorkflowError(f"workflow {alias} did not persist after import")
        return workflow

    workflow_id = str(workflow["id"])
    if definition_matches(client, workspace_id, workflow_id, manifest):
        if logger:
            logger(f"workflow READY: {alias}")
        return workflow
    raise WorkflowError(
        f"workflow {alias} has drifted from {path.name}; export the workspace "
        "copy over the managed file, or reset the workspace, then reconcile"
    )
