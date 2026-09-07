"""Fixed-target asynchronous test API; it exposes no arbitrary execution surface."""

from __future__ import annotations

import json
import os
import threading
import uuid
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .policy import (
    ALLOWED_TYPE,
    ASSET,
    CURRENT_PROPOSAL_REVISION,
    METHOD,
    ROUTE,
    SCENARIO,
    validate_proposal,
)

STATE = Path(os.environ.get("GYM_JOB_DIR", "/var/lib/gym/jobs"))
TOKEN = os.environ.get("GYM_TEST_API_TOKEN", "")
INGRESS = "http://bunkerweb:8080"
MAX_BODY = 16_384
TIMEOUT = 60
ALLOWED_KINDS = {"scan", "verify", "benign", "apply_rule", "evaluate"}
POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gym003-job")
LOCK = threading.RLock()


def now() -> str:
    return datetime.now(UTC).isoformat()


def context(run_id: str) -> dict[str, Any]:
    path = STATE / run_id
    path.mkdir(parents=True, exist_ok=True)
    return {
        "run_id": run_id,
        "scenario": SCENARIO,
        "asset": ASSET,
        "ingress": INGRESS,
        "host_header": ASSET,
        "host": ASSET,
        "evidence_dir": path,
        "state_dir": STATE.parent / "state",
        "timeout": TIMEOUT,
    }


def record_path(run_id: str) -> Path:
    return STATE / f"{run_id}.json"


def write_record(record: dict[str, Any]) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    temporary = record_path(record["run_id"]).with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    temporary.replace(record_path(record["run_id"]))


def read_record(run_id: str) -> dict[str, Any] | None:
    if not run_id.startswith("run-") or any(c not in "0123456789abcdef-" for c in run_id[4:]):
        return None
    path = record_path(run_id)
    return json.loads(path.read_text()) if path.is_file() else None


def _dispatch(kind: str, ctx: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    if kind == "scan":
        from .scanner import run_scan
        return run_scan(ctx)
    if kind == "verify":
        from .probe import verify
        return verify(ctx)
    if kind == "benign":
        from .traffic import run_benign_suite
        return run_benign_suite(ctx)
    if kind == "evaluate":
        from .acceptance import evaluate
        from .waf import WAFClient
        waf = WAFClient.from_env()
        ctx["waf_client"] = waf
        if hasattr(waf, "run_failure_guards"):
            ctx["failure_guards_runner"] = waf.run_failure_guards
        return evaluate(ctx)
    if kind == "apply_rule":
        return apply_rule(ctx, request)
    raise ValueError("unsupported job kind")


def apply_rule(ctx: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    from .probe import verify
    from .traffic import run_benign_suite
    from .waf import WAFClient

    mode = str(request.get("mode", "")).upper()
    revision = int(request.get("proposal_revision", 0))
    if revision != CURRENT_PROPOSAL_REVISION:
        raise ValueError("stale proposal revision")
    proposal = request.get("proposal") or {
        "scenario": SCENARIO,
        "revision": revision,
        "route": ROUTE,
        "method": METHOD,
        "allowed_content_type": ALLOWED_TYPE,
    }
    policy = validate_proposal(proposal, expected_revision=CURRENT_PROPOSAL_REVISION)
    client = WAFClient.from_env()
    with LOCK:
        before = verify(ctx)
        snapshot = client.snapshot()
        applied: dict[str, Any] | None = None
        rollback = {"attempted": False, "succeeded": None}
        try:
            applied = client.apply_policy(policy.as_dict(), mode)
            activation = client.wait_active(applied)
            if not activation.get("active"):
                raise RuntimeError("BunkerWeb did not activate the proposed rule")
            after = verify(ctx)
            benign = run_benign_suite(ctx)
            events = client.events(before.get("started_at", ctx.get("started_at")), [applied["rule_id"]])
            benign_ok = benign.get("passed") is True
            if mode == "BLOCK":
                before_verdict = before.get("verdict")
                pre_change_impact = before_verdict in {
                    "confirmed_file_read",
                    "confirmed_rce",
                }
                existing_block = (
                    before_verdict == "blocked_by_waf"
                    and applied.get("idempotent") is True
                )
                success = (
                    (pre_change_impact or existing_block)
                    and after.get("verdict") == "blocked_by_waf"
                    and bool(events)
                    and benign_ok
                )
            else:
                success = after.get("verdict") in {
                    "confirmed_file_read",
                    "confirmed_rce",
                    "blocked_by_waf",
                } and bool(events) and benign_ok
            if not success:
                raise RuntimeError("post-change attack, event correlation, or benign checks failed")
            return {
                "verdict": (
                    "mitigated at tested ingress"
                    if mode == "BLOCK"
                    else (
                        "logging active; existing block preserved"
                        if after.get("verdict") == "blocked_by_waf"
                        else "observed, not blocked"
                    )
                ),
                "rule": applied,
                "rule_id": applied["rule_id"],
                "proposal_revision": revision,
                "mode": mode,
                "before_attack": before,
                "before_verdict": before.get("verdict"),
                "after_attack": after,
                "after_verdict": after.get("verdict"),
                "benign": benign,
                "waf_events": events,
                "rollback": rollback,
            }
        except Exception:
            rollback["attempted"] = True
            restored = client.restore(snapshot)
            rollback["succeeded"] = bool(restored.get("active"))
            if not rollback["succeeded"]:
                raise RuntimeError("rule operation failed and rollback failed")
            raise


def run_job(record: dict[str, Any], request: dict[str, Any]) -> None:
    record["status"] = "running"
    record["started_at"] = now()
    write_record(record)
    ctx = context(record["run_id"])
    ctx["started_at"] = record["started_at"]
    try:
        from .operation_lock import exclusive_operation

        with exclusive_operation(ctx["state_dir"]):
            result = _dispatch(record["kind"], ctx, request)
        record.update(result)
        record["status"] = "completed"
    except Exception as exc:
        record["status"] = "inconclusive"
        record["verdict"] = "inconclusive"
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        record["finished_at"] = now()
        for field, default in (("evidence", []), ("benign", {}), ("waf_events", []), ("cleanup", {})):
            record.setdefault(field, default)
        try:
            from .evidence_store import upload_job
            record["evidence"] = upload_job(record, Path(ctx["evidence_dir"]))
        except Exception as exc:
            record["status"] = "inconclusive"
            record["verdict"] = "inconclusive"
            record["error"] = f"evidence persistence failed: {type(exc).__name__}: {exc}"
        write_record(record)


def submit(request: dict[str, Any]) -> dict[str, Any]:
    allowed = {"kind", "scenario", "case_id", "proposal_revision", "mode", "proposal"}
    if set(request) - allowed:
        raise ValueError("request contains unsupported fields")
    if request.get("scenario") != SCENARIO or request.get("kind") not in ALLOWED_KINDS:
        raise ValueError("unknown fixed scenario or job kind")
    idempotency_key = None
    if request["kind"] == "apply_rule":
        if not request.get("case_id"):
            raise ValueError("apply_rule requires case_id")
        idempotency_key = "|".join(
            (
                SCENARIO,
                str(request["case_id"]),
                str(request.get("proposal_revision", "")),
                str(request.get("mode", "")).upper(),
            )
        )
    submission_lock = LOCK if idempotency_key else nullcontext()
    with submission_lock:
        if idempotency_key:
            for path in STATE.glob("run-*.json") if STATE.exists() else ():
                existing = json.loads(path.read_text())
                if (
                    existing.get("idempotency_key") == idempotency_key
                    and existing.get("status") in {"queued", "running"}
                ):
                    return existing
        run_id = f"run-{uuid.uuid4()}"
        record = {
            "run_id": run_id,
            "kind": request["kind"],
            "scenario": SCENARIO,
            "case_id": request.get("case_id"),
            "status": "queued",
            "created_at": now(),
            "started_at": None,
            "finished_at": None,
            "verdict": None,
            "idempotency_key": idempotency_key,
        }
        write_record(record)
        POOL.submit(run_job, record, request)
        return record


def reconcile_interrupted_jobs() -> None:
    """Fail closed for work that cannot survive a test API restart."""

    if not STATE.exists():
        return
    for path in STATE.glob("run-*.json"):
        record = json.loads(path.read_text())
        if record.get("status") not in {"queued", "running"}:
            continue
        record.update(
            {
                "status": "inconclusive",
                "verdict": "inconclusive",
                "error": "job interrupted by test API restart",
                "finished_at": now(),
            }
        )
        write_record(record)


class Handler(BaseHTTPRequestHandler):
    server_version = "gym003-test-api/1"

    def _json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        return bool(TOKEN) and self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "scenario": SCENARIO})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if path.startswith("/v1/jobs/"):
            record = read_record(path.removeprefix("/v1/jobs/"))
            self._json(HTTPStatus.OK if record else HTTPStatus.NOT_FOUND, record or {"error": "not found"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if urlsplit(self.path).path != "/v1/jobs":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > MAX_BODY:
                raise ValueError("invalid request size")
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError("JSON object required")
            self._json(HTTPStatus.ACCEPTED, submit(request))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})

    def log_message(self, format: str, *args: object) -> None:
        print(f"[gym-003-test-api] {self.address_string()} {format % args}", flush=True)


def main() -> None:
    if not TOKEN:
        raise RuntimeError("GYM_TEST_API_TOKEN is required")
    STATE.mkdir(parents=True, exist_ok=True)
    reconcile_interrupted_jobs()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()
