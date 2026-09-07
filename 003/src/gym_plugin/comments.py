"""Safe, idempotent case execution comments."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Callable

from gymctl.http import ClientLike


_SENSITIVE_KEYS = re.compile(
    r"(^|_)(authorization|cookie|password|passwd|secret|token|api_?key|credential|"
    r"session|target|host(?:name|_header)?|command|payload|"
    r"extracted_(?:value|secret|credential))($|_)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_URL = re.compile(r"(?i)\b(?:https?|s3)://[^\s,;]+")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
)


class CommentError(RuntimeError):
    pass


def _sanitize_url(value: str) -> str:
    return _URL.sub("[REDACTED_URL]", value)


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


def _items(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _benign_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"passed": None, "transactions": []}
    transactions = []
    for item in _items(value.get("transactions")):
        if not isinstance(item, dict):
            continue
        transactions.append(
            {
                key: item.get(key)
                for key in (
                    "name",
                    "status",
                    "passed",
                    "required",
                    "receipt_confirmed",
                )
                if key in item
            }
        )
    return {"passed": value.get("passed"), "transactions": transactions}


def _waf_event_summary(value: Any) -> list[dict[str, Any]]:
    events = []
    for item in _items(value):
        if not isinstance(item, dict):
            continue
        events.append(
            {
                key: item.get(key)
                for key in (
                    "rule_id",
                    "mode",
                    "blocked",
                    "audit_correlated",
                    "timestamp",
                    "unique_id",
                )
                if key in item
            }
        )
    return events


def _rule_summary(rule: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    value = rule if isinstance(rule, dict) else {}
    return {
        "rule_id": value.get("rule_id", result.get("rule_id", "not-applicable")),
        "revision": value.get(
            "revision", result.get("proposal_revision", "unknown")
        ),
        "mode": value.get("mode", result.get("mode", "not-applicable")),
        "idempotent": value.get("idempotent"),
    }


def render_execution_comment(
    result: Mapping[str, Any],
    *,
    task_id: str,
    execution_id: str,
) -> str:
    """Render a concise automated evidence record without sensitive details."""

    clean = sanitize(dict(result))
    rule = _rule_summary(clean.get("rule"), clean)
    rollback = clean.get("rollback")
    if rollback is None:
        rollback = clean.get("cleanup")
    benign = _benign_summary(clean.get("benign"))
    waf_events = _waf_event_summary(clean.get("waf_events"))
    evidence_count = len(_items(clean.get("evidence")))
    record = {
        "task_id": sanitize(task_id),
        "execution_id": sanitize(execution_id),
        "run_id": clean.get("run_id", "unknown"),
        "verdict": clean.get("verdict", "unknown"),
        "before_verdict": clean.get("before_verdict", "unknown"),
        "after_verdict": clean.get(
            "after_verdict", clean.get("verdict", "unknown")
        ),
        "rule": rule,
        "benign": benign,
        "correlated_waf_events": waf_events,
        "evidence_record_count": evidence_count,
        "rollback": rollback,
    }
    if clean.get("error"):
        record["error"] = clean["error"]
    marker = f"<!-- gym-003-execution:{execution_id} -->"
    lines = [
        "## Automated evidence · Firewall change verification",
        "",
        f"**The control run completed with `{clean.get('verdict', 'unknown')}`.**",
        "",
        "> System generated. This record supplies evidence for Analyst review; "
        "it is not an Analyst judgment.",
        "",
        "| Review field | Value |",
        "| --- | --- |",
        f"| Status | `{clean.get('verdict', 'unknown')}` |",
        "| Malice | Pending Analyst judgment |",
        "| Action | Review the control outcome and remaining application risk |",
        "| Context | Route-scoped firewall control |",
        "",
        "### What the workflow found",
        "",
        f"- Attack verdict changed from `{clean.get('before_verdict', 'unknown')}` "
        f"to `{clean.get('after_verdict', clean.get('verdict', 'unknown'))}`.",
        f"- Required application traffic passed: `{benign.get('passed')}`.",
        f"- Correlated firewall events recorded: `{len(waf_events)}`.",
        f"- Rollback state: `{_json(rollback)}`.",
        "",
        "```mermaid",
        "flowchart LR",
        f'    A["Before<br/>{clean.get("before_verdict", "unknown")}"] --> '
        f'B["{rule.get("mode", "not-applicable")} control<br/>revision '
        f'{rule.get("revision", "unknown")}"]',
        f'    B --> C["After<br/>{clean.get("after_verdict", clean.get("verdict", "unknown"))}"]',
        f'    B --> D["Required traffic<br/>{benign.get("passed")}"]',
        "```",
        "",
        "### What this means",
        "",
        "These observations describe one controlled execution. The Analyst must "
        "decide whether they support mitigation and document the residual application risk.",
        "",
        "### What needs review",
        "",
        "Confirm the tested attack is denied, required traffic remains compatible, "
        "firewall evidence is correlated, and any failed run restored the prior state.",
        "",
        "### Sanitized evidence",
        "",
        f"```json\n{_json(record)}\n```",
    ]
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
