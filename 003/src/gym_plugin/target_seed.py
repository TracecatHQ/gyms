"""Idempotently seed the two fixed n8n workflows used by Gym 003."""

from __future__ import annotations

import base64
import http.client
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


TARGET = "http://n8n-target:5678"
WORKFLOW_DIR = Path(__file__).resolve().parents[2] / "assets" / "workflows"
WORKFLOW_FILES = ("supplier-intake.json", "order-update.json")
AUTH_CAPSULE_PATH = "/tmp/gym-003-auth.json"
AUTH_CAPSULE_WORKFLOW_NAME = "Gym 003 bootstrap auth capsule"


class SeedError(RuntimeError):
    pass


class TargetSession:
    def __init__(self, timeout: float = 15) -> None:
        self.timeout = timeout
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        parsed = urlsplit(TARGET)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.timeout)
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "Connection": "close"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    pair = value.split(";", 1)[0]
                    if "=" in pair:
                        cookie_key, cookie_value = pair.split("=", 1)
                        self.cookies[cookie_key] = cookie_value
            decoded: Any = None
            if raw:
                decoded = json.loads(raw.decode("utf-8"))
                if isinstance(decoded, dict) and set(decoded) == {"data"}:
                    decoded = decoded["data"]
            return response.status, decoded
        finally:
            connection.close()


def _load_workflows() -> list[dict[str, Any]]:
    workflows = []
    for filename in WORKFLOW_FILES:
        path = WORKFLOW_DIR / filename
        workflow = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(workflow, dict) or not workflow.get("name"):
            raise SeedError(f"invalid managed workflow fixture: {filename}")
        workflows.append(workflow)
    return workflows


def _session_identity(session: TargetSession) -> tuple[str, str]:
    """Extract the minimal reusable claims from n8n's own trusted login cookie."""

    token = session.cookies.get("n8n-auth", "")
    parts = token.split(".")
    if len(parts) != 3:
        raise SeedError("n8n bootstrap did not issue a valid authentication cookie")
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SeedError("n8n bootstrap issued a malformed authentication cookie") from exc
    if not isinstance(payload, dict):
        raise SeedError("n8n bootstrap issued a malformed authentication cookie")
    user_id = payload.get("id")
    auth_hash = payload.get("hash")
    if not all(isinstance(value, str) and 1 <= len(value) <= 256 for value in (user_id, auth_hash)):
        raise SeedError("n8n bootstrap cookie lacked the required authentication claims")
    return user_id, auth_hash


def _auth_capsule_workflow(identity: tuple[str, str]) -> dict[str, Any]:
    """Build the fixed one-shot workflow that writes a small stable probe fixture."""

    user_id, auth_hash = identity
    return {
        "name": AUTH_CAPSULE_WORKFLOW_NAME,
        "active": False,
        "nodes": [
            {
                "parameters": {},
                "id": "954c18c6-b27b-484f-86a8-9005ef02e47c",
                "name": "Manual Trigger",
                "type": "n8n-nodes-base.manualTrigger",
                "typeVersion": 1,
                "position": [0, 0],
            },
            {
                "parameters": {
                    "values": {
                        "string": [
                            {"name": "id", "value": user_id},
                            {"name": "hash", "value": auth_hash},
                        ]
                    },
                    "options": {},
                },
                "id": "6673405d-2640-4814-ab91-0cbff97fec7e",
                "name": "Select authentication claims",
                "type": "n8n-nodes-base.set",
                "typeVersion": 1,
                "position": [240, 0],
            },
            {
                "parameters": {
                    "operation": "toJson",
                    "mode": "once",
                    "binaryPropertyName": "data",
                    "options": {"format": False, "fileName": "gym-003-auth.json"},
                },
                "id": "8b228ce8-cf5f-4c5b-9983-c2590aa05d99",
                "name": "Create authentication capsule",
                "type": "n8n-nodes-base.convertToFile",
                "typeVersion": 1.1,
                "position": [480, 0],
            },
            {
                "parameters": {
                    "operation": "write",
                    "fileName": AUTH_CAPSULE_PATH,
                    "dataPropertyName": "data",
                    "options": {},
                },
                "id": "8d2fe035-f626-4f4f-a929-db17999364c7",
                "name": "Write authentication capsule",
                "type": "n8n-nodes-base.readWriteFile",
                "typeVersion": 1,
                "position": [720, 0],
            },
        ],
        "connections": {
            "Manual Trigger": {
                "main": [[{"node": "Select authentication claims", "type": "main", "index": 0}]]
            },
            "Select authentication claims": {
                "main": [[{"node": "Create authentication capsule", "type": "main", "index": 0}]]
            },
            "Create authentication capsule": {
                "main": [[{"node": "Write authentication capsule", "type": "main", "index": 0}]]
            },
        },
        "settings": {"executionOrder": "v1"},
    }


def _execution_completed(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get("finished") is True or value.get("status") == "success":
            return True
        return any(_execution_completed(item) for item in value.values())
    if isinstance(value, list):
        return any(_execution_completed(item) for item in value)
    return False


def _write_auth_capsule(
    session: TargetSession,
    identity: tuple[str, str],
    timeout: float,
) -> None:
    workflow = _auth_capsule_workflow(identity)
    status, created = session.request("POST", "/rest/workflows", workflow)
    if status not in (200, 201) or not isinstance(created, dict) or not created.get("id"):
        raise SeedError(f"creating authentication capsule workflow returned HTTP {status}")
    workflow_id = str(created["id"])
    cleanup_status = 0
    try:
        status, result = session.request(
            "POST",
            f"/rest/workflows/{workflow_id}/run?partialExecutionVersion=-1",
            {"workflowData": created, "runData": {}},
        )
        if status not in (200, 201) or not isinstance(result, dict):
            raise SeedError(f"writing authentication capsule returned HTTP {status}")
        if not _execution_completed(result):
            execution_id = result.get("executionId")
            if not execution_id:
                raise SeedError("authentication capsule execution returned no identifier")
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                status, execution = session.request(
                    "GET", f"/rest/executions/{execution_id}?includeData=true"
                )
                if status == 200 and _execution_completed(execution):
                    break
                time.sleep(0.2)
            else:
                raise SeedError("authentication capsule execution did not finish before timeout")
    finally:
        cleanup_status, _ = session.request("DELETE", f"/rest/workflows/{workflow_id}")
    if cleanup_status not in (200, 204):
        raise SeedError(
            f"removing authentication capsule workflow returned HTTP {cleanup_status}"
        )


def seed_target(context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    if context.get("target", TARGET) != TARGET:
        raise SeedError("the seed target is fixed server-side")
    timeout = float(context.get("timeout", 15))
    if not 1 <= timeout <= 60:
        raise SeedError("timeout must be between 1 and 60 seconds")

    session = TargetSession(timeout)
    login = {
        "email": os.environ.get("GYM_N8N_STAFF_EMAIL", "operator@gym.invalid"),
        "password": os.environ.get("GYM_N8N_STAFF_PASSWORD", "Gym003-DevelopmentOnly"),
    }
    status, _ = session.request("POST", "/rest/login", login)
    if status != 200:
        setup = {
            **login,
            "firstName": "Gym",
            "lastName": "Administrator",
        }
        setup_status, _ = session.request("POST", "/rest/owner/setup", setup)
        if setup_status != 200:
            raise SeedError(
                f"n8n bootstrap login/setup returned HTTP {status}/{setup_status}"
            )

    status, listing = session.request("GET", "/rest/workflows?limit=250")
    if status != 200 or not isinstance(listing, dict):
        raise SeedError(f"n8n workflow listing returned HTTP {status}")
    existing = listing.get("data", [])
    if not isinstance(existing, list):
        raise SeedError("n8n workflow listing was malformed")

    managed: dict[str, list[dict[str, Any]]] = {}
    for item in existing:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            managed.setdefault(item["name"], []).append(item)

    for stale in managed.get(AUTH_CAPSULE_WORKFLOW_NAME, []):
        stale_status, _ = session.request("DELETE", f"/rest/workflows/{stale['id']}")
        if stale_status not in (200, 204):
            raise SeedError("failed to remove a stale authentication capsule workflow")

    reconciled: list[dict[str, Any]] = []
    for fixture in _load_workflows():
        copies = managed.get(fixture["name"], [])
        workflow_id: str
        if copies:
            workflow_id = str(copies[0]["id"])
            update = dict(fixture)
            update["active"] = True
            if copies[0].get("versionId"):
                update["versionId"] = copies[0]["versionId"]
            status, result = session.request(
                "PATCH", f"/rest/workflows/{workflow_id}?forceSave=true", update
            )
            if status != 200:
                raise SeedError(f"updating managed workflow returned HTTP {status}")
            for duplicate in copies[1:]:
                duplicate_status, _ = session.request("DELETE", f"/rest/workflows/{duplicate['id']}")
                if duplicate_status not in (200, 204):
                    raise SeedError("failed to remove a duplicate managed workflow")
        else:
            create = dict(fixture)
            create["active"] = False
            status, result = session.request("POST", "/rest/workflows", create)
            if status not in (200, 201) or not isinstance(result, dict) or not result.get("id"):
                raise SeedError(f"creating managed workflow returned HTTP {status}")
            workflow_id = str(result["id"])
            activate = dict(fixture)
            activate["active"] = True
            if result.get("versionId"):
                activate["versionId"] = result["versionId"]
            status, _ = session.request(
                "PATCH", f"/rest/workflows/{workflow_id}?forceSave=true", activate
            )
            if status != 200:
                raise SeedError(f"activating managed workflow returned HTTP {status}")
        reconciled.append({"name": fixture["name"], "id": workflow_id, "active": True})

    deadline = time.monotonic() + timeout
    expected = {item["id"] for item in reconciled}
    active_ids: set[str] = set()
    while time.monotonic() < deadline:
        status, active = session.request("GET", "/rest/active-workflows")
        if status == 200 and isinstance(active, list):
            active_ids = {str(value) for value in active}
            if expected <= active_ids:
                break
        time.sleep(0.25)
    if not expected <= active_ids:
        raise SeedError("managed workflows did not become active before timeout")
    _write_auth_capsule(session, _session_identity(session), timeout)
    return {
        "status": "ready",
        "workflows": reconciled,
        "auth_capsule": {"path": AUTH_CAPSULE_PATH, "refreshed": True},
    }


if __name__ == "__main__":
    print(json.dumps(seed_target(), sort_keys=True))
