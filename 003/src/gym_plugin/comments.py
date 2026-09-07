"""Safe, idempotent Gym 003 case execution comments."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from gymctl.http import ClientLike


_SENSITIVE_KEYS = re.compile(
    r"(^|_)(authorization|cookie|password|passwd|secret|token|api_?key|credential|"
    r"session|extracted_(?:value|secret|credential))($|_)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
)
_SENSITIVE_QUERY = {
    "access_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "secret",
    "token",
}


class CommentError(RuntimeError):
    pass


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    query = [
        (key, "[REDACTED]" if key.lower() in _SENSITIVE_QUERY else item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{hostname}{port}"
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def sanitize(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact credentials while retaining reviewable evidence metadata."""

    if key is not None and _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): sanitize(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        cleaned = _BEARER.sub("Bearer [REDACTED]", value)
        cleaned = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", cleaned)
        return _sanitize_url(cleaned)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _json(value: Any) -> str:
    return json.dumps(sanitize(value), sort_keys=True, ensure_ascii=True)


def render_execution_comment(
    result: Mapping[str, Any],
    *,
    task_id: str,
    execution_id: str,
) -> str:
    """Render the required mitigation audit record without extracted secrets."""

    clean = sanitize(dict(result))
    rule = clean.get("rule") if isinstance(clean.get("rule"), dict) else {}
    rollback = clean.get("rollback")
    if rollback is None:
        rollback = clean.get("cleanup")
    marker = f"<!-- gym-003-execution:{execution_id} -->"
    lines = [
        "## Gym 003 workflow result",
        "",
        f"- Task: `{task_id}`",
        f"- Execution: `{execution_id}`",
        f"- Test run: `{clean.get('run_id', 'unknown')}`",
        f"- Rule: `{rule.get('id', clean.get('rule_id', 'not-applicable'))}`",
        f"- Rule revision: `{rule.get('revision', clean.get('proposal_revision', 'unknown'))}`",
        f"- Mode: `{rule.get('mode', clean.get('mode', 'not-applicable'))}`",
        f"- Before verdict: `{clean.get('before_verdict', 'unknown')}`",
        f"- After verdict: `{clean.get('after_verdict', clean.get('verdict', 'unknown'))}`",
        f"- Rollback: `{_json(rollback)}`",
        "",
        "### Benign tests",
        "",
        f"```json\n{_json(clean.get('benign', []))}\n```",
        "",
        "### Correlated WAF events",
        "",
        f"```json\n{_json(clean.get('waf_events', []))}\n```",
        "",
        "### Evidence",
        "",
        f"```json\n{_json(clean.get('evidence', []))}\n```",
    ]
    if clean.get("error"):
        lines.extend(("", "### Error", "", f"```json\n{_json(clean['error'])}\n```"))
    lines.extend(("", marker))
    return "\n".join(lines)


def post_execution_comment(
    client: ClientLike,
    request: Callable[..., Any],
    *,
    workspace_id: str,
    case_id: str,
    task_id: str,
    execution_id: str,
    result: Mapping[str, Any],
) -> bool:
    """Post once per workflow execution; return False when already present."""

    marker = f"<!-- gym-003-execution:{execution_id} -->"
    base = f"/workspaces/{workspace_id}/cases/{case_id}/comments"
    comments = request(client, "GET", base)
    if not isinstance(comments, list):
        raise CommentError("Tracecat case comment list response is malformed")
    if any(
        isinstance(comment, dict) and marker in str(comment.get("content", ""))
        for comment in comments
    ):
        return False
    request(
        client,
        "POST",
        base,
        body={
            "content": render_execution_comment(
                result, task_id=task_id, execution_id=execution_id
            )
        },
        expected=(201,),
    )
    return True
