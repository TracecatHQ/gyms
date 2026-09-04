"""Idempotently seed the BOTSv3 case queue and analyst preset."""
from __future__ import annotations
import csv, json, os
from pathlib import Path
from typing import Any
import httpx

ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2]))
ENTITLEMENTS = {"custom_registry", "git_sync", "agent_addons", "case_addons", "rbac_addons", "service_accounts", "workspace_chat", "watchtower"}

class ReconcileError(RuntimeError): pass
def log(message: str) -> None: print(f"[gym-reconciler] {message}", flush=True)

def request(client: httpx.Client, method: str, url: str, *, expected=(200,), **kwargs):
    response = client.request(method, url, **kwargs)
    if response.status_code not in expected:
        raise ReconcileError(f"{method} {url} returned {response.status_code}: {response.text[:500]}")
    return response.json() if response.content else None

def login(client: httpx.Client) -> str:
    response = client.post("/auth/login", data={"username": os.environ["TRACEcat_TENANT_EMAIL"], "password": os.environ["TRACEcat_TENANT_PASSWORD"]})
    if response.status_code not in (200, 204): raise ReconcileError(f"login failed: {response.status_code}")
    workspaces = request(client, "GET", "/workspaces")
    if not isinstance(workspaces, list) or len(workspaces) != 1: raise ReconcileError("expected exactly one gym workspace")
    workspace_id = str(workspaces[0]["id"])
    client.headers["x-tracecat-role-workspace-id"] = workspace_id
    client.params = {"workspace_id": workspace_id}
    return workspace_id

def verify_entitlements(client: httpx.Client) -> None:
    payload = request(client, "GET", "/organization/entitlements")
    observed = {str(k) for k, v in payload.items() if v is True} if isinstance(payload, dict) else set()
    if observed != ENTITLEMENTS: raise ReconcileError(f"entitlement drift: {sorted(observed)}")

def source_cases() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with (ROOT / "data/alerts.csv").open(newline="") as stream:
        for row in csv.DictReader(stream):
            event = row["event_time"]; day, hour = event[:10], event[11:13]
            alert = json.loads(row["payload_json"])
            payload = {
                "gym_id": "002", "alert_id": row["alert_id"], "provider": row["provider"], "product": row["product"],
                "alert_type": row["alert_type"], "event_time": event, "resource": row["resource"],
                "event_object_url": f"http://minio:9000/botsv3/botsv3_{day}_{hour}.jsonl.gz", "alert": alert,
            }
            rows.append({"summary": alert.get("title") or row["alert_type"],
                         "description": alert.get("description") or "Investigate this BOTSv3 alert using the attached event object.",
                         "status": "new", "priority": "high" if row["severity"] in ("high", "critical") else "medium",
                         "severity": row["severity"] if row["severity"] in {"low", "medium", "high", "critical"} else "unknown",
                         "payload": payload})
    if len(rows) != 34 or len({r["payload"]["alert_id"] for r in rows}) != 34: raise ReconcileError("expected 34 unique source alerts")
    return rows

def list_managed_cases(client: httpx.Client) -> dict[str, dict]:
    payload = request(client, "GET", "/cases", params={"limit": 100, "include_payload": "true"})
    items = payload.get("items", []) if isinstance(payload, dict) else []
    managed: dict[str, dict] = {}
    for case in items:
        data = case.get("payload") or {}
        if data.get("gym_id") == "002":
            alert_id = data.get("alert_id")
            if alert_id in managed: raise ReconcileError(f"duplicate managed case: {alert_id}")
            managed[str(alert_id)] = case
    return managed

def reconcile_cases(client: httpx.Client) -> None:
    desired = source_cases(); existing = list_managed_cases(client)
    for case in desired:
        if case["payload"]["alert_id"] not in existing:
            request(client, "POST", "/cases", json=case, expected=(201,))
    final = list_managed_cases(client)
    if set(final) != {c["payload"]["alert_id"] for c in desired}: raise ReconcileError("managed case queue verification failed")
    log(f"case queue READY: {len(final)} cases")

def desired_preset(client: httpx.Client) -> dict | None:
    manifest = json.loads((ROOT / "agent-preset.json").read_text())
    model = request(client, "GET", "/agent/default-model-selection")
    if not isinstance(model, dict) or not all(model.get(k) for k in ("model_name", "model_provider", "catalog_id")):
        log("agent preset pending: configure an organization default model, then run `just reconcile`"); return None
    providers = request(client, "GET", "/agent/providers/status")
    status_key = "custom-model-provider" if model.get("custom_provider_id") else model["model_provider"]
    if not isinstance(providers, dict) or providers.get(status_key) is not True:
        log(f"agent preset pending: configure credentials for {model['model_provider']}, then run `just reconcile`"); return None
    return {k: manifest[k] for k in ("name", "slug", "description", "actions", "namespaces", "tool_approvals", "agents", "retries", "enable_thinking", "enable_internet_access")} | {
        "instructions": (ROOT / "ANALYST_INSTRUCTIONS.md").read_text().strip(), "model_name": model["model_name"],
        "model_provider": model["model_provider"], "catalog_id": model["catalog_id"], "mcp_integrations": [], "skills": []}

def reconcile_preset(client: httpx.Client, workspace_id: str) -> None:
    desired = desired_preset(client)
    if desired is None: return
    base = f"/workspaces/{workspace_id}/agent/presets"; rows = request(client, "GET", base)
    matches = [r for r in rows if r.get("slug") == desired["slug"] or r.get("name") == desired["name"]]
    if len(matches) > 1: raise ReconcileError("multiple matching analyst presets")
    if matches:
        preset_id = str(matches[0]["id"]); request(client, "PATCH", f"{base}/{preset_id}", json=desired)
    else:
        created = request(client, "POST", base, json=desired, expected=(200, 201)); preset_id = str(created["id"])
    actual = request(client, "GET", f"{base}/{preset_id}")
    drift = [key for key, value in desired.items() if actual.get(key) != value]
    if drift: raise ReconcileError(f"analyst preset drift: {drift}")
    log("analyst preset READY")

def reconcile() -> None:
    with httpx.Client(base_url=os.environ["TRACEcat_INTERNAL_API_URL"], timeout=60, follow_redirects=True) as client:
        request(client, "GET", "/health"); workspace = login(client); verify_entitlements(client); reconcile_cases(client); reconcile_preset(client, workspace)
    log("READY: BOTSv3 case queue and available preset state are reconciled")

def status() -> None:
    with httpx.Client(base_url=os.environ["TRACEcat_INTERNAL_API_URL"], timeout=60, follow_redirects=True) as client:
        request(client, "GET", "/health"); workspace = login(client); managed = list_managed_cases(client)
        rows = request(client, "GET", f"/workspaces/{workspace}/agent/presets")
        preset = any(r.get("slug") == "gym-002-soc-t1-analyst" for r in rows)
        log(f"cases={len(managed)}/34 preset={'ready' if preset else 'pending-model'}")
