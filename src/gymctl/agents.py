"""Shared Tracecat agent-session and evaluation artifact primitives."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from . import tracecat
from .http import ClientLike


SENSITIVE_KEY = re.compile(
    r"authorization|cookie|password|secret|token|api[-_]?key|credential", re.I
)
TRANSIENT_ERROR = re.compile(
    r"\b(429|500|502|503|504)\b|timeout|timed out|connection reset|temporar", re.I
)


class AgentRuntimeError(RuntimeError):
    pass


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise AgentRuntimeError(f"required environment variable is missing: {name}")
    return value


def sanitize(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"(?i)Bearer\s+[A-Za-z0-9._~+\-/]+=*", "Bearer [REDACTED]", value
        )
        return value if len(value) <= 20000 else value[:20000] + "…[truncated]"
    return value


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(sanitize(value), indent=2, sort_keys=True) + "\n")


class TracecatAPI:
    def __init__(
        self,
        base_url: str | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        import httpx

        self.httpx = httpx
        self.client = httpx.Client(
            base_url=base_url or required_env("TRACEcat_INTERNAL_API_URL"),
            timeout=httpx.Timeout(timeout_seconds, connect=15.0),
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> Any:
        try:
            return tracecat.request_json(
                self.client,
                method,
                path,
                body=body,
                expected=expected,
                **kwargs,
            )
        except tracecat.TracecatError as exc:
            raise AgentRuntimeError(str(exc)) from exc

    def login(self, email: str | None = None, password: str | None = None) -> str:
        try:
            workspace_id = tracecat.login(self.client, email, password)
        except tracecat.TracecatError as exc:
            raise AgentRuntimeError(str(exc)) from exc
        return workspace_id

    def stream_message(
        self,
        workspace_id: str,
        session_id: str,
        *,
        message: str,
        model_name: str,
        model_provider: str,
        timeout_seconds: int,
    ) -> None:
        body = {
            "kind": "vercel",
            "model": model_name,
            "model_provider": model_provider,
            "message": {
                "id": str(uuid.uuid4()),
                "role": "user",
                "parts": [{"type": "text", "text": message}],
            },
        }
        path = f"/workspaces/{workspace_id}/agent/sessions/{session_id}/messages"
        timeout = self.httpx.Timeout(timeout_seconds, connect=15.0)
        with self.client.stream("POST", path, json=body, timeout=timeout) as response:
            if response.status_code != 200:
                response.read()
                raise AgentRuntimeError(str(tracecat.response_error(response)))
            for _ in response.iter_lines():
                pass


def find_preset(api: TracecatAPI, workspace_id: str, slug: str) -> dict[str, Any]:
    base = f"/workspaces/{workspace_id}/agent/presets"
    rows = api.request_json("GET", base)
    if not isinstance(rows, list):
        raise AgentRuntimeError("Tracecat preset list response is malformed")
    matches = [row for row in rows if isinstance(row, dict) and row.get("slug") == slug]
    if len(matches) != 1:
        raise AgentRuntimeError(f"expected exactly one preset with slug {slug!r}")
    preset = api.request_json("GET", f"{base}/{matches[0]['id']}")
    if not isinstance(preset, dict) or not preset.get("current_version_id"):
        raise AgentRuntimeError(f"preset {slug!r} has no current version")
    return preset


def create_session(
    api: TracecatAPI,
    workspace_id: str,
    preset: dict[str, Any],
    *,
    title: str,
    entity_type: str,
    entity_id: str,
) -> dict[str, Any]:
    expected_tools = preset.get("actions") or []
    expected_mcp = preset.get("mcp_integrations") or []
    session = api.request_json(
        "POST",
        f"/workspaces/{workspace_id}/agent/sessions",
        body={
            "title": title,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "tools": expected_tools,
            "mcp_integrations": expected_mcp,
            "agent_preset_id": preset["id"],
            "agent_preset_version_id": preset["current_version_id"],
        },
        expected=(200, 201),
    )
    if not isinstance(session, dict) or not session.get("id"):
        raise AgentRuntimeError("Tracecat did not return a created session id")
    session_id = str(session["id"])
    session_path = f"/workspaces/{workspace_id}/agent/sessions/{session_id}"
    try:
        actual = api.request_json("GET", session_path)
        # Tracecat may supply entity-specific defaults when an empty tool list
        # is posted. Tool access must match the pinned preset exactly.
        if isinstance(actual, dict) and actual.get("tools") != expected_tools:
            api.request_json("PATCH", session_path, body={"tools": expected_tools})
            actual = api.request_json("GET", session_path)
        if (
            not isinstance(actual, dict)
            or actual.get("entity_type") != entity_type
            or str(actual.get("entity_id")) != entity_id
            or actual.get("tools") != expected_tools
            or actual.get("mcp_integrations") != expected_mcp
            or str(actual.get("agent_preset_id")) != str(preset["id"])
            or str(actual.get("agent_preset_version_id"))
            != str(preset["current_version_id"])
        ):
            raise AgentRuntimeError(
                "created session does not match its pinned preset and entity"
            )
    except Exception as exc:
        try:
            api.request_json("DELETE", session_path, expected=(204, 404))
        except Exception as cleanup_error:
            exc.add_note(
                f"Invalid session {session_id} could not be deleted: {cleanup_error}"
            )
        raise
    return actual


def delete_preset_sessions(
    client: ClientLike,
    workspace_id: str,
    *,
    preset_slug: str,
    title_prefix: str,
) -> int:
    """Delete only gym-titled sessions attached to one exact preset slug."""

    try:
        preset_base = f"/workspaces/{workspace_id}/agent/presets"
        rows = tracecat.request_json(client, "GET", preset_base)
        if not isinstance(rows, list):
            raise AgentRuntimeError("Tracecat preset list response is malformed")
        matches = [
            row
            for row in rows
            if isinstance(row, dict) and row.get("slug") == preset_slug
        ]
        if len(matches) > 1:
            raise AgentRuntimeError(
                f"multiple presets match cleanup slug {preset_slug!r}"
            )
        if not matches:
            return 0
        preset_id = str(matches[0]["id"])
        session_base = f"/workspaces/{workspace_id}/agent/sessions"
        sessions = tracecat.request_json(
            client,
            "GET",
            session_base,
            params={
                "entity_type": "agent_preset",
                "entity_id": preset_id,
                "limit": 100,
            },
        )
        if not isinstance(sessions, list):
            raise AgentRuntimeError("Tracecat preset-session list is malformed")
        candidates = [
            row
            for row in sessions
            if isinstance(row, dict)
            and isinstance(row.get("id"), str)
            and isinstance(row.get("title"), str)
            and row["title"].startswith(title_prefix)
            and row.get("entity_type") == "agent_preset"
            and str(row.get("entity_id")) == preset_id
        ]
        for row in candidates:
            tracecat.request_json(
                client,
                "DELETE",
                f"{session_base}/{row['id']}",
                expected=(204, 404),
            )
        return len(candidates)
    except tracecat.TracecatError as exc:
        raise AgentRuntimeError(str(exc)) from exc


def read_session(
    api: TracecatAPI, workspace_id: str, session_id: str
) -> dict[str, Any]:
    session = api.request_json(
        "GET", f"/workspaces/{workspace_id}/agent/sessions/{session_id}/vercel"
    )
    if not isinstance(session, dict):
        raise AgentRuntimeError("Tracecat returned a malformed session")
    if session.get("last_error"):
        raise AgentRuntimeError(f"Tracecat agent run failed: {session['last_error']}")
    return session


def session_artifacts(
    session: dict[str, Any],
) -> tuple[str, list[dict[str, Any]]]:
    messages = session.get("messages")
    if not isinstance(messages, list):
        raise AgentRuntimeError("Tracecat session has no message history")
    reports: list[str] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        parts = message.get("parts")
        if not isinstance(parts, list):
            continue
        texts: list[str] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "text" and isinstance(part.get("text"), str):
                texts.append(part["text"])
                continue
        if texts:
            reports.append("\n".join(texts).strip())
    if not reports or not reports[-1]:
        raise AgentRuntimeError(
            "Tracecat session completed with an empty or malformed report"
        )
    return reports[-1], extract_tool_calls(messages)


def extract_tool_calls(messages: list[Any]) -> list[dict[str, Any]]:
    """Extract and sanitize tool-call artifacts from Vercel-format messages."""

    calls: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        parts = message.get("parts")
        if not isinstance(parts, list):
            continue
        for part in parts:
            if not isinstance(part, dict):
                continue
            part_type = part.get("type")
            is_tool = part_type == "dynamic-tool" or (
                isinstance(part_type, str) and part_type.startswith("tool-")
            )
            if not is_tool:
                continue
            tool_name = part.get("toolName")
            if not isinstance(tool_name, str) and isinstance(part_type, str):
                tool_name = part_type.removeprefix("tool-")
            calls.append(
                {
                    "tool_name": tool_name,
                    "tool_call_id": part.get("toolCallId"),
                    "state": part.get("state"),
                    "input": sanitize(part.get("input")),
                    "output": sanitize(part.get("output")),
                    "error": sanitize(part.get("errorText"), "error"),
                }
            )
    return calls


def case_snapshot(api: TracecatAPI, workspace_id: str, case_id: str) -> dict[str, Any]:
    case = api.request_json("GET", f"/workspaces/{workspace_id}/cases/{case_id}")
    comments = api.request_json(
        "GET", f"/workspaces/{workspace_id}/cases/{case_id}/comments"
    )
    if not isinstance(case, dict) or not isinstance(comments, list):
        raise AgentRuntimeError("Tracecat returned malformed case state")
    return {"case": case, "comments": comments}


def state_fingerprint(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)


def is_transient(exc: Exception) -> bool:
    import httpx

    return (
        isinstance(exc, (httpx.TimeoutException, httpx.NetworkError))
        or bool(TRANSIENT_ERROR.search(str(exc)))
        or "malformed" in str(exc).lower()
        or "empty" in str(exc).lower()
    )
