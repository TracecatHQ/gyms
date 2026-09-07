"""Deterministic benign transactions for the Gym 003 business routes."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any

from .probe import (
    FORM_PATH,
    SCENARIO,
    FixedHTTPSession,
    _safe_response_fingerprint,
    _validated_context,
    _write_json,
)


ORDER_PATH = "/webhook/order-update"
STAFF_LOGIN_PATH = "/rest/login"
HEALTH_PATH = "/healthz"
UPLOAD_BOUNDARY = "Gym003Boundary7MA4YWxkTrZu0gW"
UPLOAD_CONTENT_TYPES = (
    f"multipart/form-data; boundary={UPLOAD_BOUNDARY}",
    f"Multipart/Form-Data; boundary={UPLOAD_BOUNDARY}; charset=UTF-8",
)
ORDER_CONTENT_TYPES = (
    "application/json",
    "Application/JSON; charset=utf-8",
)
BENIGN_ROUTE_VARIANTS = (
    FORM_PATH,
    "/form/./supplier-intake",
    "/form//supplier-intake",
    "/form/supplier-intake/",
)


def _multipart_body() -> bytes:
    lines = [
        f"--{UPLOAD_BOUNDARY}\r\n".encode(),
        b'Content-Disposition: form-data; name="field-0"; filename="supplier.txt"\r\n',
        b"Content-Type: text/plain\r\n\r\n",
        b"approved supplier document\n",
        f"\r\n--{UPLOAD_BOUNDARY}--\r\n".encode(),
    ]
    return b"".join(lines)


def _record(name: str, status: int, body: bytes, *, required: bool = True, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "passed": 200 <= status < 400,
        "required": required,
        **_safe_response_fingerprint(body),
        **extra,
    }


def run_benign_suite(context: dict[str, Any]) -> dict[str, Any]:
    """Run business traffic through the fixed WAF ingress.

    Credentials are fixed bootstrap values used only for the staff login health
    transaction.  Passwords, cookies, and response bodies are never retained.
    Normalization variants are observations: acceptance compares their status to
    baseline so an application's stable 404 does not become a false regression.
    """

    evidence_dir, timeout = _validated_context(context)
    session = FixedHTTPSession(timeout=timeout)
    transactions: list[dict[str, Any]] = []
    try:
        upload_body = _multipart_body()
        for index, content_type in enumerate(UPLOAD_CONTENT_TYPES):
            status, _, body = session.request(
                "POST",
                FORM_PATH,
                body=upload_body,
                headers={"Content-Type": content_type},
            )
            transactions.append(
                _record(
                    "supplier_upload",
                    status,
                    body,
                    content_type=content_type,
                    variant=index,
                    required=index == 0,
                )
            )

        for route in BENIGN_ROUTE_VARIANTS[1:]:
            status, _, body = session.request(
                "POST",
                route,
                body=upload_body,
                headers={"Content-Type": UPLOAD_CONTENT_TYPES[0]},
            )
            transactions.append(
                _record(
                    "supplier_upload_route_normalization",
                    status,
                    body,
                    required=False,
                    route=route,
                )
            )

        order_id = "gym-003-order-1001"
        order_body = json.dumps(
            {"order_id": order_id, "status": "accepted", "supplier_id": "supplier-001"},
            separators=(",", ":"),
        ).encode()
        for index, content_type in enumerate(ORDER_CONTENT_TYPES):
            status, _, body = session.request(
                "POST",
                ORDER_PATH,
                body=order_body,
                headers={"Content-Type": content_type},
            )
            receipt_seen = order_id.encode() in body or b'"received":true' in body.replace(b" ", b"")
            item = _record(
                "order_update_downstream_receipt",
                status,
                body,
                content_type=content_type,
                variant=index,
            )
            item["passed"] = item["passed"] and receipt_seen
            item["receipt_confirmed"] = receipt_seen
            transactions.append(item)

        credentials = {
            "email": os.environ.get("GYM_N8N_STAFF_EMAIL", "operator@gym.invalid"),
            "password": os.environ.get("GYM_N8N_STAFF_PASSWORD", "Gym003-DevelopmentOnly"),
        }
        status, _, body = session.request(
            "POST",
            STAFF_LOGIN_PATH,
            body=json.dumps(credentials, separators=(",", ":")).encode(),
            headers={"Content-Type": "application/json"},
        )
        transactions.append(_record("staff_authentication", status, body))
        session.cookies.clear()

        status, _, body = session.request("GET", HEALTH_PATH)
        transactions.append(_record("health_check", status, body))
    except (OSError, TimeoutError) as exc:
        transactions.append(
            {
                "name": "suite_transport",
                "status": None,
                "passed": False,
                "required": True,
                "error": type(exc).__name__,
            }
        )

    required = [item for item in transactions if item.get("required", True)]
    passed = bool(required) and all(item.get("passed") is True for item in required)
    evidence = {
        "scenario": SCENARIO,
        "suite": "benign-business-transactions",
        "passed": passed,
        "transactions": transactions,
        "request_fixture_sha256": hashlib.sha256(_multipart_body()).hexdigest(),
    }
    path = evidence_dir / SCENARIO / "benign" / f"{uuid.uuid4().hex}.json"
    _write_json(path, evidence)
    return {"passed": passed, "transactions": transactions, "evidence": [str(path)]}
