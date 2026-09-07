"""Shared Tracecat workspace-secret reconciliation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from . import tracecat
from .http import ClientLike


DEFAULT_ENVIRONMENT = "default"


class SecretError(RuntimeError):
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
        raise SecretError(str(exc)) from exc


def inventory(client: ClientLike, workspace_id: str) -> dict[str, dict[str, Any]]:
    """Return managed-visible secret metadata by name.

    Values are never returned by the API, so reconciliation compares the key
    names a secret declares, not the values behind them.
    """
    rows = _request(client, "GET", f"/workspaces/{workspace_id}/secrets")
    if not isinstance(rows, list):
        raise SecretError("secret inventory response is malformed")
    return {
        str(row.get("name")): row
        for row in rows
        if isinstance(row, dict) and row.get("name")
    }


def reconcile_secret(
    client: ClientLike,
    workspace_id: str,
    *,
    name: str,
    keys: dict[str, str],
    description: str,
    environment: str = DEFAULT_ENVIRONMENT,
    logger: Callable[[str], None] | None = None,
) -> None:
    """Create or update one workspace secret so it holds exactly ``keys``.

    Secret values cannot be read back, so an existing secret is always rewritten
    rather than compared: that keeps a rotated credential in .env authoritative
    without leaking the current value into logs or drift output.
    """
    base = f"/workspaces/{workspace_id}/secrets"
    body = {
        "type": "custom",
        "name": name,
        "description": description,
        "environment": environment,
        "keys": [{"key": key, "value": value} for key, value in sorted(keys.items())],
    }
    existing = inventory(client, workspace_id).get(name)
    if existing is None:
        _request(client, "POST", base, body=body, expected=(201,))
        if logger:
            logger(f"secret created: {name} ({', '.join(sorted(keys))})")
        return
    _request(
        client,
        "POST",
        f"{base}/{existing['id']}",
        body=body,
        expected=(204,),
    )
    if logger:
        logger(f"secret updated: {name} ({', '.join(sorted(keys))})")


def verify_secret(
    client: ClientLike, workspace_id: str, name: str, keys: set[str]
) -> None:
    """Fail when a managed secret is missing or does not declare exactly ``keys``."""
    row = inventory(client, workspace_id).get(name)
    if row is None:
        raise SecretError(f"managed secret {name} is missing")
    actual = {str(key) for key in row.get("keys") or []}
    if actual != keys:
        raise SecretError(
            f"managed secret {name} declares {sorted(actual)}, expected {sorted(keys)}"
        )
