"""Deterministic, server-targeted BunkerWeb custom-configuration client."""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .policy import CURRENT_PROPOSAL_REVISION, Policy, render_modsecurity, validate_proposal


SERVICE = "supplier.intake.test"
CONFIG_NAME = "gym003_supplier_content_type"
CONFIG_PATH = f"/configs/{SERVICE}/modsec/{CONFIG_NAME}"
LOCK = threading.RLock()


class WAFError(RuntimeError):
    pass


class WAFClient:
    def __init__(self, api_url: str, username: str, password: str, ingress: str, events_file: Path):
        if api_url != "http://bw-api:8888" or ingress != "http://bunkerweb:8080":
            raise WAFError("WAF endpoints are fixed server-side")
        if not username or not password:
            raise WAFError("BunkerWeb management credentials are required")
        self.api_url = api_url
        self.ingress = ingress
        self.events_file = events_file
        self._authorization = base64.b64encode(f"{username}:{password}".encode()).decode()

    @classmethod
    def from_env(cls) -> "WAFClient":
        return cls(
            os.environ.get("BUNKERWEB_API_URL", "http://bw-api:8888"),
            os.environ.get("BUNKERWEB_API_USERNAME", "gym-admin"),
            os.environ.get("BUNKERWEB_API_TOKEN", ""),
            os.environ.get("GYM_WAF_INGRESS", "http://bunkerweb:8080"),
            Path(os.environ.get("GYM_WAF_EVENTS_FILE", "/var/lib/gym/jobs/waf-events.jsonl")),
        )

    def _api(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        for attempt in range(10):
            request = urllib.request.Request(
                self.api_url + path,
                method=method,
                data=data,
                headers={"Authorization": f"Basic {self._authorization}", "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    raw = response.read()
                    return response.status, json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    payload = {"error": "non-JSON BunkerWeb response"}
                if exc.code != 429 or attempt == 9:
                    return exc.code, payload
                retry_after = exc.headers.get("Retry-After", "1")
                try:
                    delay = min(5.0, max(0.25, float(retry_after)))
                except ValueError:
                    delay = 1.0
                time.sleep(delay)
        raise AssertionError("unreachable")

    def _get(self) -> dict[str, Any] | None:
        status, payload = self._api("GET", CONFIG_PATH + "?with_data=true")
        if status == 404:
            return None
        if status != 200 or not isinstance(payload.get("config"), dict):
            raise WAFError(f"BunkerWeb config read failed with HTTP {status}")
        return payload["config"]

    @staticmethod
    def _body(data: str) -> dict[str, Any]:
        return {"service": SERVICE, "type": "modsec", "name": CONFIG_NAME, "data": data, "is_draft": False}

    def _write(self, data: str) -> None:
        current = self._get()
        method, path, expected = ("PATCH", CONFIG_PATH, 200) if current else ("POST", "/configs", 201)
        status, payload = self._api(method, path, self._body(data))
        if status != expected or payload.get("status") != "success":
            raise WAFError(f"BunkerWeb config write failed with HTTP {status}")

    def snapshot(self) -> dict[str, Any]:
        with LOCK:
            current = self._get()
            return {"schema_version": 1, "configs": [] if current is None else [current]}

    def apply_policy(self, policy: dict[str, Any], mode: str) -> dict[str, Any]:
        checked = validate_proposal(policy, expected_revision=CURRENT_PROPOSAL_REVISION)
        requested_mode = mode.upper()
        rule_id, rule = render_modsecurity(checked, requested_mode)
        with LOCK:
            current = self._get()
            current_data = str((current or {}).get("data", ""))
            # Once either companion rule exists, converge in both directions to
            # LOG first + BLOCK second. Repeated task execution therefore cannot
            # trade observability for enforcement or enforcement for logging.
            other_mode = "BLOCK" if requested_mode == "LOG_ONLY" else "LOG_ONLY"
            other_id, _ = render_modsecurity(checked, other_mode)
            if f"id:{other_id}" in current_data or ("id:9300301" in current_data and "id:9300302" in current_data):
                log_id, log_rule = render_modsecurity(checked, "LOG_ONLY")
                block_id, block_rule = render_modsecurity(checked, "BLOCK")
                combined = log_rule.rstrip() + "\n" + block_rule
                idempotent = current_data == combined
                if not idempotent:
                    self._write(combined)
                return self._result(checked, requested_mode, rule_id, combined, requested_mode, idempotent) | {
                    "active_modes": ["LOG_ONLY", "BLOCK"],
                    "active_rule_ids": [log_id, block_id],
                }
            idempotent = current_data == rule
            if not idempotent:
                self._write(rule)
            return self._result(checked, requested_mode, rule_id, rule, requested_mode, idempotent)

    @staticmethod
    def _result(policy: Policy, mode: str, rule_id: int, data: str, requested_mode: str, idempotent: bool) -> dict[str, Any]:
        return {
            "service": SERVICE,
            "type": "modsec",
            "name": CONFIG_NAME,
            "revision": policy.revision,
            "mode": mode,
            "requested_mode": requested_mode,
            "rule_id": rule_id,
            "data": data,
            "idempotent": idempotent,
        }

    def restore(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        if set(snapshot) not in ({"configs"}, {"schema_version", "configs"}) or snapshot.get("schema_version", 1) != 1:
            raise WAFError("invalid WAF snapshot")
        configs = snapshot["configs"]
        if not isinstance(configs, list) or len(configs) > 1:
            raise WAFError("invalid WAF snapshot config set")
        with LOCK:
            if not configs:
                if self._get() is not None:
                    status, payload = self._api("DELETE", CONFIG_PATH)
                    if status != 200 or payload.get("status") != "success":
                        raise WAFError(f"BunkerWeb config delete failed with HTTP {status}")
                expected = {"schema_version": 1, "configs": []}
            else:
                config = configs[0]
                if not isinstance(config, dict) or not isinstance(config.get("data"), str):
                    raise WAFError("invalid WAF snapshot data")
                self._write(config["data"])
                expected = {"schema_version": 1, "configs": [config]}
            activation = self.wait_active(expected)
            if not activation.get("active"):
                raise WAFError("BunkerWeb did not restore the snapshotted dataplane state")
            return expected | activation | {"restored": True}

    def _trigger(self, mode: str, rule_id: int) -> tuple[int, str]:
        marker = "Gym003WAFActivation"
        body = json.dumps(
            {
                "data": {},
                "files": {
                    "field-0": {
                        "filepath": "/home/node/.n8n/config",
                        "originalFilename": "activation-check.bin",
                        "mimetype": "application/octet-stream",
                        "size": 64,
                    }
                },
            },
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.ingress + "/form/supplier-intake",
            method="POST",
            data=body,
            headers={"Host": SERVICE, "Content-Type": "application/json", "X-Gym-Activation": str(rule_id)},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
                return response.status, marker
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code, marker

    @staticmethod
    def _dataplane_passed(status: int) -> bool:
        return 200 <= status < 500 and status not in {401, 403, 406, 415, 429}

    def _trigger_with_events(
        self, mode: str, rule_id: int, rule_ids: list[int]
    ) -> tuple[int, dict[int, list[dict[str, Any]]]]:
        before = {
            item: {str(event.get("unique_id")) for event in self.events(0, [item])}
            for item in rule_ids
        }
        triggered_at = int(datetime.now(UTC).timestamp()) - 1
        status, _ = self._trigger(mode, rule_id)
        deadline = time.monotonic() + 5
        observed: dict[int, list[dict[str, Any]]] = {item: [] for item in rule_ids}
        while time.monotonic() < deadline:
            for item in rule_ids:
                observed[item] = [
                    event
                    for event in self.events(triggered_at, [item])
                    if str(event.get("unique_id")) not in before[item]
                ]
            if all(observed.values()):
                break
            time.sleep(0.25)
        return status, observed

    def wait_active(self, expected: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + 90
        configs = expected.get("configs")
        absent_observations = 0
        while time.monotonic() < deadline:
            current = self._get()
            if isinstance(configs, list):
                if not configs and current is None:
                    before = {
                        str(event.get("unique_id"))
                        for event in self.events(0, [9300301, 9300302])
                    }
                    triggered_at = int(datetime.now(UTC).timestamp()) - 1
                    status, _ = self._trigger("ABSENT", 0)
                    time.sleep(1)
                    new_events = [
                        event
                        for event in self.events(triggered_at, [9300301, 9300302])
                        if str(event.get("unique_id")) not in before
                    ]
                    if self._dataplane_passed(status) and not new_events:
                        absent_observations += 1
                        if absent_observations >= 3:
                            return {"active": True, "state": "absent", "status": status}
                        time.sleep(2)
                        continue
                absent_observations = 0
                if configs and current and current.get("data") == configs[0].get("data"):
                    data = str(configs[0].get("data", ""))
                    if "id:9300301" in data and "id:9300302" in data:
                        status, events = self._trigger_with_events(
                            "BLOCK", 9300302, [9300301, 9300302]
                        )
                        if status == 403 and events[9300301] and any(
                            event.get("blocked") is True for event in events[9300302]
                        ):
                            return {"active": True, "state": "restored", "status": status, "rule_ids": [9300301, 9300302]}
                    elif "id:9300302" in data:
                        status, events = self._trigger_with_events("BLOCK", 9300302, [9300302])
                        if status == 403 and any(
                            event.get("blocked") is True for event in events[9300302]
                        ):
                            return {"active": True, "state": "restored", "status": status}
                    elif "id:9300301" in data:
                        status, events = self._trigger_with_events("LOG_ONLY", 9300301, [9300301])
                        if self._dataplane_passed(status) and events[9300301]:
                            return {"active": True, "state": "restored", "status": status}
            else:
                wanted = str(expected.get("data", ""))
                if current and current.get("data") == wanted:
                    if "id:9300301" in wanted and "id:9300302" in wanted:
                        status, events = self._trigger_with_events(
                            "BLOCK", 9300302, [9300301, 9300302]
                        )
                        if status == 403 and events[9300301] and any(
                            event.get("blocked") is True for event in events[9300302]
                        ):
                            return {"active": True, "status": status, "rule_ids": [9300301, 9300302]}
                        time.sleep(2)
                        continue
                    if expected["mode"] == "BLOCK":
                        rule_id = int(expected["rule_id"])
                        status, events = self._trigger_with_events("BLOCK", rule_id, [rule_id])
                        if status == 403 and any(
                            event.get("blocked") is True for event in events[rule_id]
                        ):
                            return {"active": True, "status": status, "rule_id": expected["rule_id"]}
                    if expected["mode"] == "LOG_ONLY":
                        rule_id = int(expected["rule_id"])
                        status, events = self._trigger_with_events("LOG_ONLY", rule_id, [rule_id])
                        if self._dataplane_passed(status) and events[rule_id]:
                            return {"active": True, "status": status, "rule_id": expected["rule_id"]}
            time.sleep(2)
        return {"active": False, "reason": "activation_timeout"}

    def events(self, since: Any, rule_ids: list[int]) -> list[dict[str, Any]]:
        allowed = {9300301, 9300302}
        wanted = {int(value) for value in rule_ids}
        if not wanted or not wanted <= allowed:
            raise WAFError("event query is restricted to managed rule IDs")
        if isinstance(since, (int, float)):
            threshold = datetime.fromtimestamp(float(since), UTC)
        else:
            threshold = datetime.fromisoformat(str(since).replace("Z", "+00:00"))
            if threshold.tzinfo is None:
                threshold = threshold.replace(tzinfo=UTC)
        results: list[dict[str, Any]] = []
        try:
            lines = self.events_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        for line in lines:
            try:
                event = json.loads(line)
                observed = datetime.fromisoformat(event["timestamp"])
            except (ValueError, KeyError, json.JSONDecodeError):
                continue
            if event.get("rule_id") in wanted and observed >= threshold and event.get("audit_correlated") is True:
                results.append(event)
        return results[-100:]

    def run_failure_guards(self, context: dict[str, Any]) -> dict[str, bool]:
        from .policy import ALLOWED_TYPE, METHOD, ROUTE, SCENARIO

        policy = {"scenario": SCENARIO, "revision": 1, "route": ROUTE, "method": METHOD, "allowed_content_type": ALLOWED_TYPE}
        guards = {"outage_not_success": False, "malformed_proposal_rejected": False,
                  "stale_revision_rejected": False, "duplicate_click_idempotent": False,
                  "failed_reload_rolled_back": False}
        try:
            connection = http.client.HTTPConnection("127.0.0.1", 1, timeout=0.1)
            connection.request("GET", "/")
            response = connection.getresponse()
            guards["outage_not_success"] = not 200 <= response.status < 400
        except (OSError, socket.timeout):
            guards["outage_not_success"] = True
        for key, candidate in (
            ("malformed_proposal_rejected", policy | {"raw_rule": "SecRule"}),
            ("stale_revision_rejected", policy | {"revision": 0}),
        ):
            try:
                validate_proposal(candidate, expected_revision=1)
            except (ValueError, TypeError):
                guards[key] = True
        original = self.snapshot()
        try:
            first = self.apply_policy(policy, "BLOCK")
            if not self.wait_active(first).get("active"):
                return guards
            second = self.apply_policy(policy, "BLOCK")
            guards["duplicate_click_idempotent"] = second.get("idempotent") is True and first["rule_id"] == second["rule_id"]
            self._write('SecRule REQUEST_URI "@streq /form/supplier-intake" "id:9300399,phase:1,deny"\nBROKEN')
            time.sleep(5)
            malformed_probe_at = datetime.now(UTC).timestamp() - 1
            malformed_not_active = self._trigger("BLOCK", 9300302)[0] == 403
            for _ in range(20):
                if self.events(malformed_probe_at, [9300302]):
                    break
                time.sleep(0.1)
            else:
                malformed_not_active = False
            self._write(first["data"])
            prior_restored = self.wait_active(first).get("active") is True
            current = self._get()
            guards["failed_reload_rolled_back"] = (
                malformed_not_active and prior_restored and current is not None
                and current.get("data") == first["data"]
            )
        finally:
            self.restore(original)
        return guards
