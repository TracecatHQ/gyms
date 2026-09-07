#!/usr/bin/env python3
"""Small fixed-purpose downstream used by the order-update workflow."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    server_version = "gym003-receipts/1"

    def send_json(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.send_json(HTTPStatus.OK, {"status": "ok"}) if self.path == "/healthz" else self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/receipts":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 2 <= length <= 16384:
                raise ValueError
            value = json.loads(self.rfile.read(length))
            order_id = value["order_id"]
            if not isinstance(order_id, str) or not 1 <= len(order_id) <= 128:
                raise ValueError
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "invalid receipt"})
            return
        self.send_json(HTTPStatus.OK, {"received": True, "order_id": order_id})

    def log_message(self, format: str, *args: object) -> None:
        print(f"[gym-003-receipts] {format % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
