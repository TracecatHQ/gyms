#!/usr/bin/env python3
"""Exercise BunkerWeb's custom ModSecurity API on the local ARM64 host.

The test intentionally verifies observed request behavior and correlated audit
events. API success alone is never treated as activation.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
COMPOSE_FILE = HERE / "waf_gate.compose.yml"
PROJECT = "tracecat-gym-003-waf-gate"
API = "http://127.0.0.1:18888"
INGRESS = "http://127.0.0.1:39080/"
AUTH = base64.b64encode(b"gate-admin:Gate-Admin-003!").decode()
CONFIG_URL = f"{API}/configs/gate.test/modsec/gym003_gate"

RESTORE_RULE = (
    'SecRule REQUEST_HEADERS:X-Gym-Restore "@streq restore-marker" '
    '"id:1003000,phase:1,deny,status:418,log,auditlog,'
    "msg:'Gym 003 restore sentinel',tag:'gym003-waf-gate'\""
)
LOG_RULE = (
    'SecRule REQUEST_HEADERS:X-Gym-Gate "@streq log-marker" '
    '"id:1003001,phase:1,pass,log,auditlog,'
    "msg:'Gym 003 log gate',tag:'gym003-waf-gate'\""
)
BLOCK_RULE = (
    'SecRule REQUEST_HEADERS:X-Gym-Gate "@streq block-marker" '
    '"id:1003002,phase:1,deny,status:403,log,auditlog,'
    "msg:'Gym 003 block gate',tag:'gym003-waf-gate'\""
)


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            PROJECT,
            "--project-directory",
            str(HERE),
            "-f",
            str(COMPOSE_FILE),
            *args,
        ],
        check=check,
        text=True,
        capture_output=True,
    )


def api(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Basic {AUTH}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read() or b"{}")
        return error.code, payload


def ingress(header: str | None = None, value: str | None = None) -> int:
    headers = {"Host": "gate.test"}
    if header and value:
        headers[header] = value
    request = urllib.request.Request(INGRESS, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def audit_logs() -> str:
    return compose("logs", "--no-color", "audit-collector").stdout


def new_audit_contains(before: str, marker: str) -> str:
    logs = audit_logs()
    delta = logs[len(before) :]
    return delta if marker in delta else ""


def emit_log_marker_and_find(before: str) -> str:
    if ingress("X-Gym-Gate", "log-marker") != 200:
        return ""
    return new_audit_contains(before, 'id "1003001"')


def wait_for(description: str, predicate: Any, timeout: float = 90) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (OSError, TimeoutError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError(f"timed out waiting for {description}; last observation={last!r}")


def put_rule(rule: str, *, create: bool) -> None:
    if create:
        status, payload = api(
            "POST",
            "/configs",
            {
                "service": "gate.test",
                "type": "modsec",
                "name": "gym003_gate",
                "data": rule,
                "is_draft": False,
            },
        )
        expected = 201
    else:
        status, payload = api(
            "PATCH",
            "/configs/gate.test/modsec/gym003_gate",
            {
                "service": "gate.test",
                "type": "modsec",
                "name": "gym003_gate",
                "data": rule,
                "is_draft": False,
            },
        )
        expected = 200
    if status != expected or payload.get("status") != "success":
        raise RuntimeError(f"custom config write failed: HTTP {status}: {payload}")


def main() -> int:
    print("Starting digest-pinned BunkerWeb 1.6.14 ARM64 feasibility stack...")
    compose("up", "-d", "--wait", "--wait-timeout", "180")
    wait_for("BunkerWeb API", lambda: api("GET", "/health")[0] == 200)
    wait_for("unmodified ingress", lambda: ingress() == 200)

    # Ensure a prior interrupted run cannot taint this gate.
    api("DELETE", "/configs/gate.test/modsec/gym003_gate")
    wait_for(
        "API cleanup",
        lambda: api("GET", "/configs/gate.test/modsec/gym003_gate")[0] == 404,
    )
    wait_for(
        "clean deployed baseline",
        lambda: ingress("X-Gym-Restore", "restore-marker") == 200,
    )

    put_rule(RESTORE_RULE, create=True)
    wait_for(
        "initial custom config activation",
        lambda: ingress("X-Gym-Restore", "restore-marker") == 418,
    )
    status, snapshot = api("GET", "/configs/gate.test/modsec/gym003_gate?with_data=true")
    if status != 200 or snapshot.get("config", {}).get("data") != RESTORE_RULE:
        raise RuntimeError(f"snapshot mismatch: HTTP {status}: {snapshot}")
    print("PASS create+activate: restore sentinel returned HTTP 418")

    before_logs = audit_logs()
    put_rule(LOG_RULE, create=False)
    wait_for(
        "LOG-only activation and audit event",
        lambda: emit_log_marker_and_find(before_logs),
    )
    print("PASS log: request returned HTTP 200 and audit event contained rule 1003001")

    before_logs = audit_logs()
    put_rule(BLOCK_RULE, create=False)
    wait_for("BLOCK activation", lambda: ingress("X-Gym-Gate", "block-marker") == 403)
    wait_for(
        "BLOCK audit event",
        lambda: new_audit_contains(before_logs, 'id "1003002"'),
    )
    print("PASS block activation: request returned HTTP 403 and audit event contained rule 1003002")

    status, payload = api("DELETE", "/configs/gate.test/modsec/gym003_gate")
    if status != 200 or payload.get("status") != "success":
        raise RuntimeError(f"custom config delete failed: HTTP {status}: {payload}")
    wait_for("rule removal", lambda: ingress("X-Gym-Gate", "block-marker") == 200)
    wait_for("API removal", lambda: api("GET", "/configs/gate.test/modsec/gym003_gate")[0] == 404)
    print("PASS remove: API returned 404 and former block marker returned HTTP 200")

    restored = snapshot["config"]
    put_rule(str(restored["data"]), create=True)
    wait_for(
        "snapshot restoration",
        lambda: ingress("X-Gym-Restore", "restore-marker") == 418,
    )
    print("PASS restore: snapshotted sentinel became active and returned HTTP 418")

    status, payload = api("DELETE", "/configs/gate.test/modsec/gym003_gate")
    if status != 200:
        raise RuntimeError(f"final cleanup failed: HTTP {status}: {payload}")
    wait_for("final clean baseline", lambda: ingress("X-Gym-Restore", "restore-marker") == 200)
    print("PASS cleanup: gate configuration removed; ingress returned HTTP 200")
    print("FEASIBILITY GATE PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FEASIBILITY GATE FAILED: {exc}", file=sys.stderr)
        raise
