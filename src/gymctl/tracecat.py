"""Shared Tracecat API helpers used by gym plugins."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx


ENTITLEMENTS = {
    "agent_addons",
    "case_addons",
    "custom_registry",
    "git_sync",
    "rbac_addons",
    "service_accounts",
    "watchtower",
    "workspace_chat",
}


class TracecatError(RuntimeError):
    pass


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise TracecatError(f"required environment variable is missing: {name}")
    return value


def response_error(response: httpx.Response) -> TracecatError:
    detail = response.text.strip().replace("\n", " ")[-600:]
    return TracecatError(
        f"Tracecat {response.request.method} {response.request.url.path} returned {response.status_code}: {detail}"
    )


def request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    body: Any | None = None,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    if body is not None:
        kwargs["json"] = body
    response = client.request(method, url, **kwargs)
    if response.status_code not in expected:
        raise response_error(response)
    if response.status_code == 204 or not response.content:
        return None
    return response.json()


def client() -> httpx.Client:
    import httpx

    return httpx.Client(
        base_url=required_env("TRACEcat_INTERNAL_API_URL"),
        timeout=120,
        follow_redirects=True,
    )


def login(
    client: httpx.Client,
    email: str | None = None,
    password: str | None = None,
) -> str:
    response = client.post(
        "/auth/login",
        data={
            "username": email or required_env("TRACEcat_TENANT_EMAIL"),
            "password": password or required_env("TRACEcat_TENANT_PASSWORD"),
        },
    )
    if response.status_code not in (200, 204):
        raise response_error(response)
    workspaces = request_json(client, "GET", "/workspaces")
    if not isinstance(workspaces, list) or len(workspaces) != 1:
        raise TracecatError(f"expected exactly one gym workspace, found {workspaces!r}")
    workspace_id = workspaces[0].get("id")
    if not workspace_id:
        raise TracecatError("workspace response is missing an id")
    return str(workspace_id)


def verify_entitlements(client: httpx.Client) -> None:
    payload = request_json(client, "GET", "/organization/entitlements")
    if not isinstance(payload, dict):
        raise TracecatError("organization entitlement response is malformed")
    observed = {str(name) for name, enabled in payload.items() if enabled is True}
    if observed != ENTITLEMENTS:
        raise TracecatError(
            f"enterprise entitlement drift: expected={sorted(ENTITLEMENTS)}, observed={sorted(observed)}"
        )


def default_agent_model(client: httpx.Client) -> dict[str, Any]:
    selection = request_json(client, "GET", "/agent/default-model-selection")
    if not isinstance(selection, dict):
        raise TracecatError("configure an organization-default agent model in Tracecat")
    for key in ("catalog_id", "model_name", "model_provider"):
        if not isinstance(selection.get(key), str) or not selection[key]:
            raise TracecatError(f"default model selection is missing {key}")
    status = request_json(client, "GET", "/agent/providers/status")
    status_key = (
        "custom-model-provider"
        if selection.get("custom_provider_id")
        else selection["model_provider"]
    )
    if not isinstance(status, dict) or status.get(status_key) is not True:
        raise TracecatError(
            f"credentials for {selection['model_provider']} are not configured"
        )
    return selection


def paginated_items(payload: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise TracecatError(f"{description} response is malformed")
    return [item for item in payload["items"] if isinstance(item, dict)]
