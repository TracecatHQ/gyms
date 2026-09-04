#!/usr/bin/env python3
"""Reconcile Splunk data, Tracecat MCP, and the gym's agent presets."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


MCP_INTEGRATION_NAME = "Splunk — Gym 001"
MCP_APP_NAME = "Splunk_MCP_Server"
MCP_APP_VERSION = "2.0.0"
MCP_TOOLS_ENDPOINT = "/servicesNS/admin/Splunk_MCP_Server/mcp_tools"
GYM_ROOT = Path(os.environ.get("GYM_ROOT", "/opt/gym"))
HARNESS_DIR = GYM_ROOT / "benchmark/harness"
SCORECARD_FILE = GYM_ROOT / "benchmark/scorecard.json"
LOCK_FILE = GYM_ROOT / "gym.lock.json"
SPLUNK_MCP_ROLE_CAPABILITIES = {
    "list_workload_pools",
    "mcp_tool_execute",
    "select_workload_pools",
}
TRACECAT_ENTITLEMENTS = {
    "custom_registry",
    "git_sync",
    "agent_addons",
    "case_addons",
    "rbac_addons",
    "service_accounts",
    "workspace_chat",
    "watchtower",
}


class ReconcileError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gym-reconciler] {message}", flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ReconcileError(f"required environment variable {name} is missing")
    return value


def response_error(response: httpx.Response) -> ReconcileError:
    body = response.text.replace("\n", " ")[:800]
    return ReconcileError(
        f"{response.request.method} {response.request.url} returned "
        f"HTTP {response.status_code}: {body}"
    )


def request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_body: Any = None,
    expected: tuple[int, ...] = (200,),
) -> Any:
    response = client.request(
        method, url, params=params, data=data, json=json_body
    )
    if response.status_code not in expected:
        raise response_error(response)
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        raise ReconcileError(
            f"{method} {response.request.url} returned non-JSON content"
        ) from exc


def wait_for(
    description: str,
    deadline: float,
    probe: Callable[[], Any],
    interval: int = 5,
) -> Any:
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            result = probe()
            log(f"{description} is ready")
            return result
        except (httpx.HTTPError, ReconcileError) as exc:
            last_error = str(exc)
            time.sleep(interval)
    raise ReconcileError(f"timed out waiting for {description}: {last_error}")


def splunk_client() -> httpx.Client:
    return httpx.Client(
        base_url=required_env("SPLUNK_API_URL"),
        auth=(required_env("SPLUNK_ADMIN_USER"), required_env("SPLUNK_ADMIN_PASSWORD")),
        timeout=httpx.Timeout(60.0, connect=10.0),
        follow_redirects=True,
    )


def tracecat_client() -> httpx.Client:
    return httpx.Client(
        base_url=required_env("TRACEcat_INTERNAL_API_URL"),
        timeout=httpx.Timeout(60.0, connect=10.0),
        follow_redirects=True,
    )


def splunk_entries(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
        raise ReconcileError("Splunk REST response did not contain an entry list")
    return [entry for entry in payload["entry"] if isinstance(entry, dict)]


def as_epoch(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
        try:
            return int(
                datetime.fromisoformat(stripped.replace("Z", "+00:00")).timestamp()
            )
        except ValueError as exc:
            raise ReconcileError(f"cannot parse Splunk license timestamp {value!r}") from exc
    raise ReconcileError(f"cannot parse Splunk license timestamp {value!r}")


def verify_splunk_license(client: httpx.Client) -> dict[str, Any]:
    payload = request_json(
        client,
        "GET",
        "/services/licenser/licenses",
        params={"output_mode": "json", "count": 0},
    )
    locked = json.loads(LOCK_FILE.read_text())
    expected_expiration = int(
        locked["artifacts"]["splunk_license"]["expiration_time"]
    )
    matches: list[dict[str, Any]] = []
    for entry in splunk_entries(payload):
        content = entry.get("content")
        if not isinstance(content, dict):
            continue
        group_id = str(content.get("group_id", ""))
        license_type = str(content.get("type", ""))
        if group_id.lower() == "enterprise" or license_type.lower() == "enterprise":
            matches.append(content)
    if not matches:
        raise ReconcileError("Splunk did not report an installed Enterprise license")

    valid_matches: list[dict[str, Any]] = []
    observed_expirations: list[int] = []
    for content in matches:
        try:
            expiration = as_epoch(content.get("expiration_time"))
        except ReconcileError:
            continue
        observed_expirations.append(expiration)
        if expiration > int(time.time()):
            valid_matches.append(content)
    if not valid_matches:
        raise ReconcileError(
            f"Splunk Enterprise license is expired; observed expirations={observed_expirations}"
        )
    if expected_expiration not in observed_expirations:
        raise ReconcileError(
            "Splunk is not using the mounted license: expected expiration "
            f"{expected_expiration}, observed {observed_expirations}"
        )
    log(
        "installed Splunk Enterprise license is valid through "
        + datetime.fromtimestamp(expected_expiration, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    return valid_matches[0]


def verify_mcp_app(client: httpx.Client) -> None:
    payload = request_json(
        client,
        "GET",
        f"/services/apps/local/{MCP_APP_NAME}",
        params={"output_mode": "json"},
    )
    entries = splunk_entries(payload)
    if len(entries) != 1:
        raise ReconcileError(f"expected one installed {MCP_APP_NAME} app")
    content = entries[0].get("content", {})
    version = str(content.get("version", "")) if isinstance(content, dict) else ""
    if version != MCP_APP_VERSION:
        raise ReconcileError(
            f"expected {MCP_APP_NAME} {MCP_APP_VERSION}, found {version or 'unknown'}"
        )
    if isinstance(content, dict) and str(content.get("disabled", "0")).lower() in {
        "1",
        "true",
    }:
        raise ReconcileError(f"{MCP_APP_NAME} is installed but disabled")
    log(f"{MCP_APP_NAME} {version} is installed")


def expected_core_mcp_tools() -> set[str]:
    payload = json.loads(LOCK_FILE.read_text())
    return {str(name) for name in payload["expectations"]["mcp"]["core_tools"]}


def splunk_mcp_tool_state(client: httpx.Client) -> tuple[dict[str, str], set[str]]:
    catalog = request_json(
        client,
        "GET",
        MCP_TOOLS_ENDPOINT,
        params={"output_mode": "json"},
    )
    if not isinstance(catalog, dict) or not isinstance(catalog.get("tools"), list):
        raise ReconcileError("Splunk MCP tool catalog response is malformed")
    core_by_name: dict[str, str] = {}
    for tool in catalog["tools"]:
        if not isinstance(tool, dict):
            continue
        metadata = tool.get("_meta")
        metadata = metadata if isinstance(metadata, dict) else {}
        name = tool.get("name")
        tool_id = tool.get("tool_id")
        if (
            metadata.get("built_in") is True
            and not metadata.get("required_app")
            and isinstance(name, str)
            and isinstance(tool_id, str)
        ):
            core_by_name[name] = tool_id

    enabled_payload = request_json(
        client,
        "GET",
        MCP_TOOLS_ENDPOINT,
        params={"output_mode": "json", "enabled_tools": "1"},
    )
    if not isinstance(enabled_payload, dict) or not isinstance(
        enabled_payload.get("enabled_tools"), list
    ):
        raise ReconcileError("Splunk MCP enabled-tool response is malformed")
    enabled_names = {
        str(row["tool_name"])
        for row in enabled_payload["enabled_tools"]
        if isinstance(row, dict) and row.get("tool_name")
    }
    return core_by_name, enabled_names


def enable_all_core_mcp_tools(client: httpx.Client) -> set[str]:
    expected = expected_core_mcp_tools()
    tools, _ = splunk_mcp_tool_state(client)
    if set(tools) != expected:
        raise ReconcileError(
            "installed Splunk MCP core tool set does not match the locked package: "
            f"expected={sorted(expected)}, observed={sorted(tools)}"
        )
    for name, tool_id in sorted(tools.items()):
        request_json(
            client,
            "POST",
            MCP_TOOLS_ENDPOINT,
            params={"output_mode": "json"},
            json_body={
                "tool_id": tool_id,
                "tool_name": name,
                "enabled": True,
                "override": True,
            },
        )
    _, enabled = splunk_mcp_tool_state(client)
    missing = expected - enabled
    if missing:
        raise ReconcileError(f"Splunk MCP tools remain disabled: {sorted(missing)}")
    log(f"explicitly enabled all {len(expected)} applicable Splunk MCP core tools")
    return expected


def splunk_object_exists(client: httpx.Client, endpoint: str) -> bool:
    response = client.get(endpoint, params={"output_mode": "json"})
    if response.status_code == 404:
        return False
    if response.status_code != 200:
        raise response_error(response)
    return True


def ensure_mcp_role_and_user(client: httpx.Client) -> None:
    role = required_env("SPLUNK_MCP_USER")
    password = required_env("SPLUNK_MCP_PASSWORD")
    role_endpoint = f"/services/authorization/roles/{quote(role, safe='')}"
    role_data = {
        "imported_roles": "user",
        "capabilities": sorted(SPLUNK_MCP_ROLE_CAPABILITIES),
        "srchIndexesAllowed": "investigation",
        "srchIndexesDefault": "investigation",
    }
    if splunk_object_exists(client, role_endpoint):
        request_json(
            client,
            "POST",
            role_endpoint,
            params={"output_mode": "json"},
            data=role_data,
        )
    else:
        request_json(
            client,
            "POST",
            "/services/authorization/roles",
            params={"output_mode": "json"},
            data={"name": role, **role_data},
            expected=(200, 201),
        )

    role_payload = request_json(
        client,
        "GET",
        role_endpoint,
        params={"output_mode": "json"},
    )
    role_entries = splunk_entries(role_payload)
    role_content = role_entries[0].get("content", {}) if role_entries else {}
    capabilities = {
        str(capability)
        for capability in (
            role_content.get("capabilities", [])
            if isinstance(role_content, dict)
            else []
        )
    }
    missing_capabilities = SPLUNK_MCP_ROLE_CAPABILITIES - capabilities
    if missing_capabilities:
        raise ReconcileError(
            f"Splunk MCP role is missing capabilities: {sorted(missing_capabilities)}"
        )

    user_endpoint = f"/services/authentication/users/{quote(role, safe='')}"
    user_data = {
        "password": password,
        "roles": role,
        "realname": "Tracecat MCP",
    }
    if splunk_object_exists(client, user_endpoint):
        request_json(
            client,
            "POST",
            user_endpoint,
            params={"output_mode": "json"},
            data=user_data,
        )
    else:
        request_json(
            client,
            "POST",
            "/services/authentication/users",
            params={"output_mode": "json"},
            data={"name": role, **user_data},
            expected=(200, 201),
        )
    log(
        f"least-privilege Splunk MCP role and user {role!r} are ready "
        f"with {len(SPLUNK_MCP_ROLE_CAPABILITIES)} required capabilities"
    )


def load_expected_counts() -> tuple[str, dict[str, int], int]:
    payload = json.loads(LOCK_FILE.read_text())["expectations"]
    events = payload["events"]
    sourcetypes = {str(key): int(value) for key, value in events["sourcetypes"].items()}
    return str(payload["splunk_index"]), sourcetypes, int(events["total"])


def current_counts(client: httpx.Client, index: str) -> dict[str, int]:
    response = client.post(
        "/services/search/jobs/export",
        data={
            "search": f"search index={index} | stats count by sourcetype | sort sourcetype",
            "earliest_time": "0",
            "latest_time": "now",
            "output_mode": "json",
        },
        timeout=120.0,
    )
    if response.status_code != 200:
        raise response_error(response)
    counts: dict[str, int] = {}
    for line in response.text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = record.get("result")
        if not isinstance(result, dict) or "sourcetype" not in result:
            continue
        counts[str(result["sourcetype"])] = int(str(result.get("count", "0")).replace(",", ""))
    return counts


def counts_summary(counts: dict[str, int], expected: dict[str, int]) -> str:
    return ", ".join(
        f"{name}={counts.get(name, 0)}/{wanted}" for name, wanted in expected.items()
    )


def wait_for_dataset(
    client: httpx.Client,
    deadline: float,
    index: str,
    expected: dict[str, int],
    expected_total: int,
) -> None:
    poll_seconds = int(os.environ.get("GYM_DATA_POLL_SECONDS", "10"))
    last_counts: dict[str, int] | None = None
    last_log = 0.0
    while time.monotonic() < deadline:
        counts = current_counts(client, index)
        unexpected = sorted(set(counts) - set(expected))
        excessive = {
            name: count
            for name, count in counts.items()
            if name in expected and count > expected[name]
        }
        if unexpected or excessive:
            raise ReconcileError(
                "dataset contains unexpected or duplicate events: "
                f"unexpected={unexpected}, excessive={excessive}"
            )
        if counts == expected and sum(counts.values()) == expected_total:
            log(f"dataset is complete: {counts_summary(counts, expected)}")
            return
        now = time.monotonic()
        if counts != last_counts or now - last_log >= 60:
            log(f"waiting for dataset: {counts_summary(counts, expected)}")
            last_counts = counts
            last_log = now
        time.sleep(poll_seconds)
    final_counts = current_counts(client, index)
    raise ReconcileError(
        "timed out waiting for exact dataset counts: "
        + counts_summary(final_counts, expected)
    )


def find_token(value: Any) -> str | None:
    if isinstance(value, dict):
        token = value.get("token")
        if isinstance(token, str) and token:
            return token
        for child in value.values():
            found = find_token(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_token(child)
            if found:
                return found
    return None


def _as_string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {part.strip() for part in value.split() if part.strip()}
    if isinstance(value, list):
        return {str(part).strip() for part in value if str(part).strip()}
    return set()


def gym_mcp_tokens(client: httpx.Client) -> list[dict[str, Any]]:
    """Return Splunk JWT rows for the gym MCP user and audience."""
    payload = request_json(
        client,
        "GET",
        "/services/authorization/tokens",
        params={
            "output_mode": "json",
            "count": 0,
            "username": required_env("SPLUNK_MCP_USER"),
        },
    )
    username = required_env("SPLUNK_MCP_USER")
    matches: list[dict[str, Any]] = []
    for entry in splunk_entries(payload):
        content = entry.get("content")
        if not isinstance(content, dict):
            continue
        claims = content.get("claims")
        claims = claims if isinstance(claims, dict) else {}
        subject = claims.get("sub", content.get("claims.sub", content.get("subject")))
        audience = claims.get("aud", content.get("claims.aud", content.get("audience")))
        if str(subject) == username and "mcp" in _as_string_set(audience):
            matches.append(entry)
    return matches


def revoke_gym_mcp_tokens(client: httpx.Client) -> None:
    """Keep token reconciliation idempotent by replacing, never accumulating, JWTs."""
    tokens = gym_mcp_tokens(client)
    username = required_env("SPLUNK_MCP_USER")
    for entry in tokens:
        content = entry.get("content")
        content = content if isinstance(content, dict) else {}
        token_id = content.get("id", entry.get("name"))
        if not isinstance(token_id, str) or not token_id:
            raise ReconcileError("Splunk returned an MCP token without a revocable id")
        request_json(
            client,
            "DELETE",
            f"/services/authorization/tokens/{quote(username, safe='')}",
            params={"output_mode": "json"},
            data={"id": token_id},
            expected=(200, 204),
        )
    if tokens:
        log(f"revoked {len(tokens)} previous gym MCP token(s) before replacement")


def mint_mcp_token(client: httpx.Client) -> str:
    # The app accepts relative durations or ISO-8601, and caps lifetime at 180 days.
    expires_on = "+15551940s"
    payload = request_json(
        client,
        "GET",
        "/servicesNS/admin/Splunk_MCP_Server/mcp_token",
        params={
            "username": required_env("SPLUNK_MCP_USER"),
            "expires_on": expires_on,
            "output_mode": "json",
        },
    )
    token = find_token(payload)
    if not token:
        raise ReconcileError("Splunk MCP token endpoint returned no token")
    token_rows = gym_mcp_tokens(client)
    if len(token_rows) != 1:
        raise ReconcileError(
            f"expected exactly one active gym MCP token after minting, found {len(token_rows)}"
        )
    log("minted an encrypted Splunk MCP bearer token (not persisted or printed)")
    return token


def mcp_result_text(result: Any) -> str:
    """Flatten the non-secret response payload of a tool call for assertions."""
    fragments: list[str] = []
    for attribute in ("structured_content", "data"):
        value = getattr(result, attribute, None)
        if value is not None:
            try:
                fragments.append(json.dumps(value, default=str, sort_keys=True))
            except TypeError:
                fragments.append(str(value))
    for block in getattr(result, "content", []) or []:
        text_value = getattr(block, "text", None)
        if isinstance(text_value, str):
            fragments.append(text_value)
        else:
            fragments.append(str(block))
    return "\n".join(fragments)


async def smoke_test_mcp(token: str, index: str, expected_total: int) -> set[str]:
    transport = StreamableHttpTransport(
        url=required_env("SPLUNK_MCP_URL"),
        headers={"Authorization": f"Bearer {token}"},
    )
    async with Client(transport, timeout=120) as client:
        tools = await client.list_tools()
        incompatible = []
        for tool in tools:
            stack = [("$", tool.inputSchema or {})]
            while stack:
                path, value = stack.pop()
                if isinstance(value, dict):
                    for key, child in value.items():
                        child_path = f"{path}.{key}"
                        if key == "pattern" and isinstance(child, str) and "(?" in child:
                            incompatible.append(f"{tool.name}:{child_path}")
                        else:
                            stack.append((child_path, child))
                elif isinstance(value, list):
                    stack.extend(
                        (f"{path}[{index}]", child)
                        for index, child in enumerate(value)
                    )
        if incompatible:
            raise ReconcileError(
                "Splunk MCP exposes JSON Schema regexes rejected by OpenAI: "
                f"{sorted(incompatible)}"
            )
        names = {tool.name for tool in tools}
        required = {"splunk_get_indexes", "splunk_run_query"}
        if not required.issubset(names):
            raise ReconcileError(
                f"Splunk MCP is missing required tools: {sorted(required - names)}"
            )
        indexes_result = await client.call_tool("splunk_get_indexes", {})
        if getattr(indexes_result, "is_error", False):
            raise ReconcileError("Splunk MCP get_indexes smoke test failed")
        indexes_text = mcp_result_text(indexes_result)
        if index not in indexes_text:
            raise ReconcileError(
                f"Splunk MCP get_indexes did not return the {index!r} index"
            )
        query_result = await client.call_tool(
            "splunk_run_query",
            {
                "query": f"search index={index} | stats count",
                "earliest_time": "0",
                "latest_time": "now",
            },
        )
        if getattr(query_result, "is_error", False):
            raise ReconcileError("Splunk MCP run_query smoke test failed")
        query_text = mcp_result_text(query_result)
        plain_total = str(expected_total)
        comma_total = f"{expected_total:,}"
        if not re.search(
            rf"(?<!\d)(?:{re.escape(plain_total)}|{re.escape(comma_total)})(?!\d)",
            query_text,
        ):
            raise ReconcileError(
                "Splunk MCP run_query did not return the exact expected count "
                f"{expected_total}"
            )
    log(
        f"Splunk MCP advertised {len(names)} tools and passed index/count smoke tests "
        f"for {expected_total} events"
    )
    return names


async def wait_for_mcp(
    token: str, index: str, expected_total: int, deadline: float
) -> set[str]:
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            return await smoke_test_mcp(token, index, expected_total)
        except Exception as exc:
            last_error = str(exc)
            await asyncio.sleep(3)
    raise ReconcileError(f"timed out waiting for Splunk MCP proxy: {last_error}")


def tracecat_login(client: httpx.Client) -> str:
    response = client.post(
        "/auth/login",
        data={
            "username": required_env("TRACEcat_TENANT_EMAIL"),
            "password": required_env("TRACEcat_TENANT_PASSWORD"),
        },
    )
    if response.status_code not in (200, 204):
        raise response_error(response)
    workspaces = request_json(client, "GET", "/workspaces")
    if not isinstance(workspaces, list) or len(workspaces) != 1:
        raise ReconcileError(
            f"expected exactly one Tracecat workspace for the gym user, found {workspaces!r}"
        )
    workspace_id = workspaces[0].get("id")
    if not workspace_id:
        raise ReconcileError("Tracecat workspace response is missing an id")
    return str(workspace_id)


def verify_tracecat_entitlements(client: httpx.Client) -> None:
    payload = request_json(client, "GET", "/organization/entitlements")
    if not isinstance(payload, dict):
        raise ReconcileError("Tracecat organization entitlement response is malformed")
    observed = {str(name) for name, enabled in payload.items() if enabled is True}
    if observed != TRACECAT_ENTITLEMENTS:
        raise ReconcileError(
            "Tracecat effective enterprise entitlements are not all enabled: "
            f"expected={sorted(TRACECAT_ENTITLEMENTS)}, observed={sorted(observed)}"
        )
    log(f"all {len(observed)} Tracecat enterprise entitlements are effective")


def integration_tools(integration: dict[str, Any]) -> list[dict[str, Any]]:
    tools = integration.get("tools")
    return (
        [tool for tool in tools if isinstance(tool, dict)]
        if isinstance(tools, list)
        else []
    )


def reconcile_tracecat_mcp(
    client: httpx.Client, workspace_id: str, token: str, remote_names: set[str]
) -> dict[str, Any]:
    base = f"/workspaces/{workspace_id}/mcp-integrations"
    existing = request_json(client, "GET", base)
    if not isinstance(existing, list):
        raise ReconcileError("Tracecat MCP integration list was not an array")
    mcp_url = required_env("SPLUNK_MCP_URL")
    candidates = [
        row
        for row in existing
        if isinstance(row, dict)
        and (row.get("name") == MCP_INTEGRATION_NAME or row.get("server_uri") == mcp_url)
    ]
    if len(candidates) > 1:
        raise ReconcileError(
            "multiple Tracecat MCP integrations match the gym name or URI; refusing to choose"
        )
    headers = json.dumps({"Authorization": f"Bearer {token}"})
    payload = {
        "name": MCP_INTEGRATION_NAME,
        "description": "Official Splunk MCP Server backed by the pinned Gym 001 dataset",
        "server_type": "http",
        "server_uri": mcp_url,
        "auth_type": "CUSTOM",
        "custom_credentials": headers,
        "timeout": 120,
    }
    if candidates:
        integration_id = str(candidates[0]["id"])
        request_json(
            client,
            "PUT",
            f"{base}/{integration_id}",
            json_body=payload,
        )
        log("updated the existing Tracecat Splunk MCP integration")
    else:
        created = request_json(
            client,
            "POST",
            base,
            json_body=payload,
            expected=(200, 201),
        )
        integration_id = str(created["id"])
        log("created the Tracecat Splunk MCP integration")

    test_result = request_json(client, "POST", f"{base}/{integration_id}/test")
    if isinstance(test_result, dict) and test_result.get("success") is False:
        raise ReconcileError(f"Tracecat MCP verification failed: {test_result}")
    integration = request_json(client, "GET", f"{base}/{integration_id}")
    tools = integration_tools(integration)
    names = {
        str(tool.get("name"))
        for tool in tools
        if tool.get("name") and tool.get("status", "available") == "available"
    }
    missing = remote_names - names
    if missing:
        raise ReconcileError(
            f"Tracecat did not discover all Splunk MCP tools: missing={sorted(missing)}"
        )
    request_json(
        client,
        "PATCH",
        f"{base}/{integration_id}/tools",
        json_body={
            "tools": [
                {"name": name, "enabled": True, "requires_approval": False}
                for name in sorted(remote_names)
            ]
        },
    )
    final = request_json(client, "GET", f"{base}/{integration_id}")
    disabled = [
        tool.get("name")
        for tool in integration_tools(final)
        if tool.get("name") in remote_names
        and (tool.get("enabled") is not True or tool.get("requires_approval") is not False)
    ]
    if disabled:
        raise ReconcileError(f"Tracecat MCP tool policies are not enabled: {disabled}")
    log(f"Tracecat MCP integration is verified with all {len(names)} tools enabled")
    return final


def load_agent_preset_definition() -> tuple[dict[str, Any], str]:
    manifest_path = HARNESS_DIR / "investigator-preset.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconcileError(f"cannot load agent preset manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ReconcileError("agent preset manifest must be a JSON object")
    prompt_filename = manifest.get("prompt_file")
    if not isinstance(prompt_filename, str) or not prompt_filename:
        raise ReconcileError("agent preset manifest is missing prompt_file")
    prompt_path = (HARNESS_DIR / prompt_filename).resolve()
    if prompt_path.parent != HARNESS_DIR.resolve():
        raise ReconcileError("agent preset prompt_file must stay inside its directory")
    try:
        prompt = prompt_path.read_text().strip()
    except OSError as exc:
        raise ReconcileError(f"cannot load agent preset prompt: {exc}") from exc
    if not prompt:
        raise ReconcileError("agent preset prompt must not be empty")
    if manifest.get("model_selection") != "organization_default":
        raise ReconcileError(
            "agent preset model_selection must be 'organization_default'"
        )
    return manifest, prompt


def default_agent_model(client: httpx.Client) -> dict[str, Any]:
    selection = request_json(client, "GET", "/agent/default-model-selection")
    if not isinstance(selection, dict):
        raise ReconcileError(
            "no default Tracecat agent model is configured; add model credentials, "
            "select an organization default model, then run `just reconcile`"
        )
    for key in ("catalog_id", "model_name", "model_provider"):
        if not isinstance(selection.get(key), str) or not selection[key]:
            raise ReconcileError(
                f"Tracecat default model selection is missing {key!r}"
            )
    provider_status = request_json(client, "GET", "/agent/providers/status")
    if not isinstance(provider_status, dict):
        raise ReconcileError("Tracecat provider status response is malformed")
    status_key = (
        "custom-model-provider"
        if selection.get("custom_provider_id")
        else selection["model_provider"]
    )
    if provider_status.get(status_key) is not True:
        raise ReconcileError(
            f"credentials for the default agent provider {selection['model_provider']!r} "
            "are not configured; add them in Tracecat, then run `just reconcile`"
        )
    return selection


def workspace_agent_model(
    client: httpx.Client, workspace_id: str, provider: str, model_name: str
) -> dict[str, Any]:
    payload = request_json(
        client, "GET", f"/workspaces/{workspace_id}/agent-models"
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ReconcileError("Tracecat workspace model response is malformed")
    matches = [
        row
        for row in payload["items"]
        if isinstance(row, dict)
        and row.get("model_provider") == provider
        and row.get("model_name") == model_name
    ]
    if len(matches) != 1:
        raise ReconcileError(
            f"evaluation grader model {provider}/{model_name} is not uniquely "
            "available to the workspace"
        )
    provider_status = request_json(client, "GET", "/agent/providers/status")
    if not isinstance(provider_status, dict) or provider_status.get(provider) is not True:
        raise ReconcileError(
            f"credentials for evaluation grader provider {provider!r} are not configured"
        )
    model = matches[0]
    if not isinstance(model.get("id"), str) or not model["id"]:
        raise ReconcileError("evaluation grader catalog entry is missing its id")
    return model


def load_grader_preset_definition() -> tuple[dict[str, Any], str, dict[str, Any]]:
    manifest_path = HARNESS_DIR / "grader-preset.json"
    scenario_path = SCORECARD_FILE
    config_path = HARNESS_DIR / "evaluation.json"
    try:
        manifest = json.loads(manifest_path.read_text())
        scenario = json.loads(scenario_path.read_text())
        evaluation = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconcileError(f"cannot load evaluation preset definition: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(scenario, dict):
        raise ReconcileError("evaluation manifests must be JSON objects")
    prompt_filename = manifest.get("prompt_file")
    if not isinstance(prompt_filename, str) or not prompt_filename:
        raise ReconcileError("evaluation grader preset is missing prompt_file")
    prompt_path = (HARNESS_DIR / prompt_filename).resolve()
    if prompt_path.parent != HARNESS_DIR.resolve():
        raise ReconcileError("evaluation grader prompt_file must stay inside its directory")
    try:
        base_prompt = prompt_path.read_text().strip()
    except OSError as exc:
        raise ReconcileError(f"cannot load evaluation grader prompt: {exc}") from exc
    if not base_prompt:
        raise ReconcileError("evaluation grader prompt must not be empty")
    judge = evaluation.get("judge")
    if not isinstance(judge, dict):
        raise ReconcileError("evaluation scenario is missing judge configuration")
    for field in ("model_provider", "model_name"):
        if manifest.get(field) != judge.get(field):
            raise ReconcileError(
                f"evaluation grader preset and scenario disagree on {field}"
            )
    if manifest.get("slug") != judge.get("preset_slug"):
        raise ReconcileError("evaluation grader preset and scenario disagree on slug")
    rubric = {
        "hard_gate": scenario.get("hard_gate"),
        "validation_gates": scenario.get("validation_gates"),
        "known_legitimate_activity": scenario.get("reference_facts", {}).get("known_legitimate_activity"),
    }
    prompt = (
        f"{base_prompt}\n\nSUPPLIED RUBRIC AND REFERENCE FACTS:\n"
        f"{json.dumps(rubric, indent=2, sort_keys=True)}"
    )
    return manifest, prompt, scenario


def desired_agent_preset(
    client: httpx.Client, mcp_integration_id: str
) -> dict[str, Any]:
    manifest, prompt = load_agent_preset_definition()
    model = default_agent_model(client)
    required_manifest_fields = {
        "name",
        "slug",
        "description",
        "actions",
        "namespaces",
        "tool_approvals",
        "agents",
        "retries",
        "enable_thinking",
        "enable_internet_access",
    }
    missing = sorted(required_manifest_fields - manifest.keys())
    if missing:
        raise ReconcileError(f"agent preset manifest is missing fields: {missing}")
    return {
        "name": manifest["name"],
        "slug": manifest["slug"],
        "description": manifest["description"],
        "instructions": prompt,
        "model_name": model["model_name"],
        "model_provider": model["model_provider"],
        "catalog_id": model["catalog_id"],
        "actions": manifest["actions"],
        "namespaces": manifest["namespaces"],
        "tool_approvals": manifest["tool_approvals"],
        "mcp_integrations": [mcp_integration_id],
        "agents": manifest["agents"],
        "retries": manifest["retries"],
        "enable_thinking": manifest["enable_thinking"],
        "enable_internet_access": manifest["enable_internet_access"],
        "skills": [],
    }


def matching_agent_presets(
    client: httpx.Client, workspace_id: str, desired: dict[str, Any]
) -> list[dict[str, Any]]:
    rows = request_json(
        client, "GET", f"/workspaces/{workspace_id}/agent/presets"
    )
    if not isinstance(rows, list):
        raise ReconcileError("Tracecat agent preset list response is malformed")
    return [
        row
        for row in rows
        if isinstance(row, dict)
        and (row.get("slug") == desired["slug"] or row.get("name") == desired["name"])
    ]


def verify_agent_preset(
    client: httpx.Client,
    workspace_id: str,
    preset_id: str,
    desired: dict[str, Any],
) -> dict[str, Any]:
    actual = request_json(
        client,
        "GET",
        f"/workspaces/{workspace_id}/agent/presets/{preset_id}",
    )
    if not isinstance(actual, dict):
        raise ReconcileError("Tracecat agent preset response is malformed")
    drifted = [key for key, value in desired.items() if actual.get(key) != value]
    if drifted:
        raise ReconcileError(
            f"Tracecat agent preset does not match Git-tracked state: {drifted}"
        )
    attachment = (
        "Splunk MCP attached"
        if desired.get("mcp_integrations")
        else "no tools or MCP integrations"
    )
    log(
        f"agent preset {desired['name']!r} is ready with model "
        f"{desired['model_provider']}/{desired['model_name']} and {attachment}"
    )
    return actual


def reconcile_agent_preset(
    client: httpx.Client, workspace_id: str, mcp_integration_id: str
) -> dict[str, Any]:
    desired = desired_agent_preset(client, mcp_integration_id)
    matches = matching_agent_presets(client, workspace_id, desired)
    if len(matches) > 1:
        raise ReconcileError(
            "multiple Tracecat agent presets match the gym name or slug; refusing to choose"
        )
    base = f"/workspaces/{workspace_id}/agent/presets"
    if matches:
        preset_id = str(matches[0]["id"])
        request_json(
            client,
            "PATCH",
            f"{base}/{preset_id}",
            json_body=desired,
        )
        log("updated the existing Tracecat SOC analyst agent preset")
    else:
        created = request_json(
            client,
            "POST",
            base,
            json_body=desired,
            expected=(200, 201),
        )
        if not isinstance(created, dict) or not created.get("id"):
            raise ReconcileError("Tracecat did not return the created agent preset id")
        preset_id = str(created["id"])
        log("created the Tracecat SOC analyst agent preset")
    return verify_agent_preset(client, workspace_id, preset_id, desired)


def desired_grader_preset(
    client: httpx.Client, workspace_id: str
) -> dict[str, Any]:
    manifest, prompt, _ = load_grader_preset_definition()
    model = workspace_agent_model(
        client,
        workspace_id,
        str(manifest["model_provider"]),
        str(manifest["model_name"]),
    )
    required = {
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
    }
    missing = sorted(required - manifest.keys())
    if missing:
        raise ReconcileError(f"evaluation grader preset is missing fields: {missing}")
    return {
        "name": manifest["name"],
        "slug": manifest["slug"],
        "description": manifest["description"],
        "instructions": prompt,
        "model_name": model["model_name"],
        "model_provider": model["model_provider"],
        "catalog_id": model["id"],
        "actions": manifest["actions"],
        "namespaces": manifest["namespaces"],
        "tool_approvals": manifest["tool_approvals"],
        "mcp_integrations": manifest["mcp_integrations"],
        "agents": manifest["agents"],
        "retries": manifest["retries"],
        "enable_thinking": manifest["enable_thinking"],
        "enable_internet_access": manifest["enable_internet_access"],
        "skills": [],
    }


def reconcile_grader_preset(
    client: httpx.Client, workspace_id: str
) -> dict[str, Any]:
    desired = desired_grader_preset(client, workspace_id)
    matches = matching_agent_presets(client, workspace_id, desired)
    if len(matches) > 1:
        raise ReconcileError(
            "multiple Tracecat evaluation grader presets match the gym name or slug; "
            "refusing to choose"
        )
    base = f"/workspaces/{workspace_id}/agent/presets"
    if matches:
        preset_id = str(matches[0]["id"])
        request_json(client, "PATCH", f"{base}/{preset_id}", json_body=desired)
        log("updated the existing Tracecat evaluation grader preset")
    else:
        created = request_json(
            client,
            "POST",
            base,
            json_body=desired,
            expected=(200, 201),
        )
        if not isinstance(created, dict) or not created.get("id"):
            raise ReconcileError("Tracecat did not return the grader preset id")
        preset_id = str(created["id"])
        log("created the Tracecat evaluation grader preset")
    return verify_agent_preset(client, workspace_id, preset_id, desired)


def reconcile() -> None:
    timeout = int(os.environ.get("GYM_RECONCILE_TIMEOUT_SECONDS", "2400"))
    deadline = time.monotonic() + timeout
    index, expected, expected_total = load_expected_counts()

    with splunk_client() as splunk:
        wait_for(
            "Splunk REST API",
            deadline,
            lambda: request_json(
                splunk,
                "GET",
                "/services/server/info",
                params={"output_mode": "json"},
            ),
        )
        wait_for(
            "valid Splunk Enterprise license",
            deadline,
            lambda: verify_splunk_license(splunk),
        )
        wait_for(
            f"{MCP_APP_NAME} {MCP_APP_VERSION}",
            deadline,
            lambda: verify_mcp_app(splunk),
        )
        expected_tool_names = wait_for(
            "Splunk MCP tool catalog",
            deadline,
            lambda: enable_all_core_mcp_tools(splunk),
        )
        ensure_mcp_role_and_user(splunk)
        wait_for_dataset(splunk, deadline, index, expected, expected_total)
        revoke_gym_mcp_tokens(splunk)
        token = mint_mcp_token(splunk)

    remote_names = asyncio.run(
        wait_for_mcp(token, index, expected_total, deadline)
    )
    if remote_names != expected_tool_names:
        raise ReconcileError(
            "Splunk MCP advertised tool set differs from enabled core tools: "
            f"expected={sorted(expected_tool_names)}, advertised={sorted(remote_names)}"
        )

    with tracecat_client() as tracecat:
        wait_for(
            "Tracecat API",
            deadline,
            lambda: request_json(tracecat, "GET", "/health"),
        )
        workspace_id = tracecat_login(tracecat)
        verify_tracecat_entitlements(tracecat)
        mcp_integration = reconcile_tracecat_mcp(
            tracecat, workspace_id, token, remote_names
        )
        reconcile_agent_preset(tracecat, workspace_id, str(mcp_integration["id"]))
        reconcile_grader_preset(tracecat, workspace_id)

    log(
        "READY: dataset, enterprise license, MCP server, Tracecat integration, "
        "SOC analyst preset, and evaluation grader preset are ready"
    )


def status() -> None:
    index, expected, expected_total = load_expected_counts()
    try:
        with splunk_client() as splunk:
            verify_splunk_license(splunk)
            verify_mcp_app(splunk)
            tools, enabled = splunk_mcp_tool_state(splunk)
            expected_tools = expected_core_mcp_tools()
            log(
                f"Splunk MCP tool state "
                f"{'READY' if set(tools) == expected_tools and expected_tools <= enabled else 'DRIFTED'}: "
                f"enabled_core={len(expected_tools & enabled)}/{len(expected_tools)}"
            )
            counts = current_counts(splunk, index)
            complete = counts == expected and sum(counts.values()) == expected_total
            log(
                f"dataset {'READY' if complete else 'INGESTING'}: "
                + counts_summary(counts, expected)
            )
            tokens = gym_mcp_tokens(splunk)
            log(
                f"Splunk MCP token state {'READY' if len(tokens) == 1 else 'DRIFTED'}: "
                f"active_tokens={len(tokens)} (expected 1)"
            )
    except Exception as exc:
        log(f"Splunk status unavailable: {exc}")

    try:
        with tracecat_client() as tracecat:
            request_json(tracecat, "GET", "/health")
            workspace_id = tracecat_login(tracecat)
            verify_tracecat_entitlements(tracecat)
            base = f"/workspaces/{workspace_id}/mcp-integrations"
            rows = request_json(tracecat, "GET", base)
            matches = [
                row
                for row in rows
                if isinstance(row, dict) and row.get("name") == MCP_INTEGRATION_NAME
            ]
            if len(matches) == 1:
                tools = integration_tools(matches[0])
                enabled = sum(tool.get("enabled") is True for tool in tools)
                log(
                    f"Tracecat API READY; Splunk MCP integration present with "
                    f"{enabled}/{len(tools)} tools enabled"
                )
                integration_id = str(matches[0]["id"])
                desired = desired_agent_preset(tracecat, integration_id)
                presets = matching_agent_presets(tracecat, workspace_id, desired)
                if len(presets) == 1:
                    verify_agent_preset(
                        tracecat,
                        workspace_id,
                        str(presets[0]["id"]),
                        desired,
                    )
                else:
                    log(
                        "Tracecat SOC analyst agent preset state DRIFTED: "
                        f"matches={len(presets)}"
                    )
                grader = desired_grader_preset(tracecat, workspace_id)
                grader_matches = matching_agent_presets(
                    tracecat, workspace_id, grader
                )
                if len(grader_matches) == 1:
                    verify_agent_preset(
                        tracecat,
                        workspace_id,
                        str(grader_matches[0]["id"]),
                        grader,
                    )
                else:
                    log(
                        "Tracecat evaluation grader preset state DRIFTED: "
                        f"matches={len(grader_matches)}"
                    )
            else:
                log(f"Tracecat API READY; Splunk MCP integrations found={len(matches)}")
    except Exception as exc:
        log(f"Tracecat status unavailable: {exc}")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "reconcile"
    try:
        if command == "reconcile":
            reconcile()
        elif command == "status":
            status()
        else:
            raise ReconcileError(f"unknown command {command!r}")
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
