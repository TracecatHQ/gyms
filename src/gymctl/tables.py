"""Shared Tracecat case-table reconciliation."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import tracecat
from .http import ClientLike


class TableError(RuntimeError):
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
        raise TableError(str(exc)) from exc


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate one managed table definition."""
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise TableError(f"cannot load table manifest {path.name}: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"name", "columns"}
        or not isinstance(manifest["name"], str)
        or not manifest["name"]
        or not isinstance(manifest["columns"], list)
        or not manifest["columns"]
    ):
        raise TableError(f"table manifest {path.name} has an invalid shape")
    seen: set[str] = set()
    for column in manifest["columns"]:
        if (
            not isinstance(column, dict)
            or set(column) != {"name", "type"}
            or not isinstance(column["name"], str)
            or not isinstance(column["type"], str)
            or not column["name"]
            or not column["type"]
        ):
            raise TableError(f"table manifest {path.name} has an invalid column")
        if column["name"] in seen:
            raise TableError(
                f"table manifest {path.name} has duplicate column {column['name']!r}"
            )
        seen.add(column["name"])
    if manifest["name"] != path.stem:
        raise TableError(f"table manifest {path.name} does not match its table name")
    return manifest


def _list_tables(client: ClientLike, base: str) -> dict[str, dict[str, Any]]:
    """Return managed-visible tables by name.

    The table list endpoint returns a plain array, not a cursor page.
    """
    rows = _request(client, "GET", base)
    if not isinstance(rows, list):
        raise TableError("table list response is malformed")
    return {
        str(row.get("name")): row
        for row in rows
        if isinstance(row, dict) and row.get("name")
    }


def _columns(table: dict[str, Any]) -> dict[str, str]:
    return {
        str(column.get("name")): str(column.get("type"))
        for column in table.get("columns") or []
        if isinstance(column, dict)
    }


def reconcile_tables(
    client: ClientLike,
    workspace_id: str,
    tables_dir: Path,
    *,
    expected_count: int,
    logger: Callable[[str], None] | None = None,
) -> list[str]:
    """Create managed tables and add any missing columns.

    Columns are only ever added. Dropping or retyping a column would destroy
    rows the gym did not create, so a conflicting type is reported for manual
    review instead of being silently reconciled.
    """
    base = f"/workspaces/{workspace_id}/tables"
    manifests = [load_manifest(path) for path in sorted(tables_dir.glob("*.json"))]
    if len(manifests) != expected_count:
        raise TableError(
            f"expected {expected_count} managed tables, found {len(manifests)}"
        )
    existing = _list_tables(client, base)
    table_ids: list[str] = []
    for manifest in manifests:
        name = manifest["name"]
        desired = {column["name"]: column["type"] for column in manifest["columns"]}
        table = existing.get(name)
        if table is None:
            created = _request(
                client,
                "POST",
                base,
                body={
                    "name": name,
                    "columns": [
                        {"name": key, "type": value}
                        for key, value in sorted(desired.items())
                    ],
                },
                expected=(201,),
            )
            table_ids.append(str(created["id"]))
            if logger:
                logger(f"table created: {name} ({len(desired)} columns)")
            continue
        table_id = str(table["id"])
        actual = _columns(_request(client, "GET", f"{base}/{table_id}"))
        conflicts = sorted(
            key for key, value in desired.items() if key in actual and actual[key] != value
        )
        if conflicts:
            raise TableError(
                f"table {name} has conflicting column types for {conflicts}; "
                "resolve manually to avoid destroying existing rows"
            )
        for key in sorted(set(desired) - set(actual)):
            _request(
                client,
                "POST",
                f"{base}/{table_id}/columns",
                body={"name": key, "type": desired[key]},
                expected=(201,),
            )
            if logger:
                logger(f"table {name}: added column {key}")
        table_ids.append(table_id)
    return table_ids


def verify_tables(
    client: ClientLike, workspace_id: str, tables_dir: Path, *, expected_count: int
) -> None:
    """Fail when a managed table is missing or lacks a declared column."""
    base = f"/workspaces/{workspace_id}/tables"
    manifests = [load_manifest(path) for path in sorted(tables_dir.glob("*.json"))]
    if len(manifests) != expected_count:
        raise TableError(
            f"expected {expected_count} managed tables, found {len(manifests)}"
        )
    existing = _list_tables(client, base)
    for manifest in manifests:
        name = manifest["name"]
        table = existing.get(name)
        if table is None:
            raise TableError(f"managed table {name} is missing")
        actual = _columns(_request(client, "GET", f"{base}/{table['id']}"))
        desired = {column["name"]: column["type"] for column in manifest["columns"]}
        missing = sorted(
            key for key, value in desired.items() if actual.get(key) != value
        )
        if missing:
            raise TableError(f"managed table {name} is missing or drifted: {missing}")
