"""Repository integrity plus read-only checks against the running Gym 001 stack."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from . import config
from .license import load_metadata
from .scenario import HARD_FAIL_GATE, canonical_scenario_hash, load_scenario
from . import reconcile


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _upstream_services(path: Path) -> set[str]:
    services: set[str] = set()
    in_services = False
    for line in path.read_text().splitlines():
        if line == "services:":
            in_services = True
            continue
        if in_services and line and not line.startswith(" "):
            break
        match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if in_services and match:
            services.add(match.group(1))
    return services


def _merged_compose() -> dict[str, Any]:
    result = subprocess.run(
        config.compose_args(
            "--profile",
            "bootstrap",
            "--profile",
            "evaluation",
            "config",
            "--format",
            "json",
        ),
        cwd=config.ROOT,
        env=config.compose_environment(),
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise ValidationError(f"Compose merge failed:\n{result.stderr}")
    return json.loads(result.stdout)


def validate() -> None:
    root = config.ROOT
    lock = config.load_lock()
    require(lock["schema_version"] == 2, "gym.lock.json schema must be 2")
    require(
        lock["gym"]
        == {
            "id": "001",
            "display_name": "The Bigger Interview",
            "compose_project": config.PROJECT,
            "component_version": "1",
        },
        "gym identity drifted",
    )

    tracecat = config.load_platform_lock()["tracecat"]
    require(
        sha256(config.REPO_ROOT / "upstream/tracecat/docker-compose.yml")
        == tracecat["compose_sha256"],
        "pristine Tracecat Compose checksum mismatch",
    )
    require(
        sha256(config.REPO_ROOT / "upstream/tracecat/Caddyfile")
        == tracecat["caddyfile_sha256"],
        "pristine Caddyfile checksum mismatch",
    )

    dataset = root / "upstream/dataset"
    require((dataset / ".git").exists(), "dataset must be a Git submodule")
    head = subprocess.run(
        ["git", "-C", str(dataset), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    require(
        head == lock["sources"]["dataset"]["commit"], "dataset gitlink commit mismatch"
    )
    for path in ("README.md", "LICENSE", "LICENSE-DATA", "conf", "logs"):
        require((dataset / path).exists(), f"dataset is missing {path}")
    logs = list((dataset / "logs").rglob("*.json.gz"))
    require(
        len(logs) == 8, f"expected eight compressed telemetry files, found {len(logs)}"
    )

    mcp = root / "assets/splunk-mcp-server_200.tgz"
    license_file = root / "assets/Splunk.License"
    require(
        sha256(mcp) == lock["artifacts"]["splunk_mcp"]["sha256"],
        "MCP archive checksum mismatch (or unresolved LFS pointer)",
    )
    metadata = load_metadata(license_file)
    for key in (
        "type",
        "group_id",
        "quota_bytes_per_day",
        "creation_time",
        "expiration_time",
        "expiration_utc",
        "sha256",
    ):
        require(
            metadata[key] == lock["artifacts"]["splunk_license"][key],
            f"Splunk license lock mismatch for {key}",
        )

    scenario = load_scenario(root / "benchmark/scenario.json")
    source = lock["sources"]["scenario"]
    require(
        source["classification"] == "derived-from-public-article",
        "scenario provenance classification drifted",
    )
    require(
        canonical_scenario_hash(scenario) == source["sha256"],
        "scenario source transcription checksum mismatch",
    )
    gates = scenario["validation_gates"]
    require(
        gates[0] == {"validation_gate": HARD_FAIL_GATE, "weight": 0},
        "disposition hard gate must be the first validation-gate row",
    )
    require(
        sum(int(gate["weight"]) for gate in gates[1:]) == 100,
        "weighted validation gates must total 100",
    )
    require(
        (root / "benchmark/agent/investigation-prompt.md").read_text().strip()
        == "Is this alert a false positive?",
        "investigation prompt must remain the minimal published-alert question",
    )
    evaluation = json.loads((root / "benchmark/evals/evaluation.json").read_text())
    require(evaluation["default_runs"] == 1, "evaluation must default to one run")
    require(
        not (root / "benchmark/harness").exists(),
        "agent and evaluation assets must not share a harness directory",
    )

    require(
        not (root / "scripts").exists(),
        "legacy ad hoc scripts directory must be removed",
    )
    required_commands = {
        "build",
        "migrate",
        "up",
        "info",
        "status",
        "wait",
        "reconcile",
        "eval",
        "logs",
        "down",
        "restart",
        "clean-restart",
        "reset-evals",
        "reset",
        "rotate-license",
        "check-upstreams",
        "update-upstreams",
        "update-dataset",
        "check",
    }
    justfile = (root / "Justfile").read_text()
    require(
        all(
            re.search(rf"^{re.escape(name)}(?:\s|:)", justfile, re.M)
            for name in required_commands
        ),
        "Justfile is missing public commands",
    )
    for dockerfile in (
        root / "images/splunk/Dockerfile",
        root / "images/control/Dockerfile",
    ):
        text = dockerfile.read_text().lower()
        require(
            not re.search(r"\brun\s+.*(pip|uv|apt|apk|curl|wget)", text),
            f"runtime dependency download found in {dockerfile}",
        )
    proxy_source = (root / "src/gym_plugin/mcp_proxy.py").read_text()
    require(
        "await asyncio.wait({call}, timeout=scope_seconds)" in proxy_source
        and "UPSTREAM_CLOSE_TIMEOUT_SECONDS" in proxy_source
        and "ResponseLimitingMiddleware(max_size=200_000" in proxy_source
        and 'arguments["row_limit"] = max(1, min(requested, 100))' in proxy_source,
        "Splunk MCP compatibility proxy must bound upstream requests",
    )

    merged = _merged_compose()
    services = merged["services"]
    require(
        _upstream_services(config.REPO_ROOT / "upstream/tracecat/docker-compose.yml")
        <= set(services),
        "merged Compose lost an upstream service",
    )
    require(
        all("container_name" not in service for service in services.values()),
        "merged Compose contains a fixed container name",
    )
    expected_images = {
        "splunk": config.local_image("splunk"),
        "splunk-mcp-compat": config.local_image("control"),
        "tracecat-seed": config.local_image("control"),
        "gym-reconciler": config.local_image("control"),
        "eval-runner": config.local_image("control"),
    }
    require(
        all(
            services[name]["image"] == image for name, image in expected_images.items()
        ),
        "merged Compose does not use deterministic local images",
    )
    for component in ("splunk", "control"):
        require(
            lock["images"]["local"][component]["input_sha256"]
            == config.image_input_hash(component),
            f"locked {component} image input hash is stale",
        )
    ports = [
        binding for service in services.values() for binding in service.get("ports", [])
    ]
    require(
        {(str(item.get("host_ip")), int(item.get("published"))) for item in ports}
        == {("127.0.0.1", 18080), ("127.0.0.1", 18000)},
        "ports must be only localhost 18080 and 18000",
    )
    binds: list[tuple[str, str]] = []
    for service in services.values():
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                binds.append((str(mount.get("source")), str(mount.get("target"))))
    expected_binds = {
        (
            str((root / "assets/Splunk.License").resolve()),
            "/run/gym-assets/Splunk.License",
        ),
        (str((root / "eval-results").resolve()), "/opt/gym/eval-results"),
    }
    require(set(binds) == expected_binds, f"unexpected host bind mounts: {binds}")
    require(
        "8089" not in {str(item.get("published")) for item in ports},
        "Splunk management port must not be published",
    )
    require(
        services["splunk"]["platform"] == "linux/amd64",
        "Splunk platform must be linux/amd64",
    )
    require(
        services["splunk"]["environment"].get(
            "SPLUNK_SKIP_PREINSTALL_CPU_CHECKS_CORRUPTING_DATA_IF_UNSUPPORTED"
        )
        == "1",
        "Apple Silicon Splunk CPU-check compatibility setting is missing",
    )
    for service in (
        "api",
        "worker",
        "executor",
        "agent-worker",
        "litellm",
        "agent-executor",
        "mcp",
        "migrations",
    ):
        environment = services[service].get("environment", {})
        require(
            environment.get("ENTERPRISE_EDITION") == "true",
            f"{service} enterprise mode is not enabled",
        )
        require(
            environment.get("TRACECAT__EE_MULTI_TENANT") == "true",
            f"{service} multi-tenant entitlement mode is not enabled",
        )
    require(os.stat(root / ".env").st_mode & 0o777 == 0o600, ".env must have mode 0600")
    required_services = (
        "api",
        "litellm",
        "postgres_db",
        "temporal",
        "minio",
        "redis",
        "splunk",
        "splunk-mcp-compat",
    )
    for service in required_services:
        rows = (
            config.run_compose("ps", "--quiet", service, capture=True)
            .stdout.strip()
            .splitlines()
        )
        require(len(rows) == 1, f"running stack is missing service {service}")
        state = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                rows[0],
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        require(
            state == "running healthy", f"service {service} is not healthy: {state}"
        )

    env = config.parse_env()
    from gymctl.http import Client

    with Client(
        base_url=env["PUBLIC_API_URL"], timeout=120, follow_redirects=True
    ) as client:
        reconcile.request_json(client, "GET", "/health")
        workspace_id = reconcile.tracecat_login(
            client,
            env["TRACEcat_TENANT_EMAIL"],
            env["TRACEcat_TENANT_PASSWORD"],
        )
        reconcile.verify_tracecat_entitlements(client)
        alert_case = reconcile.reconcile_alert_case(
            client, workspace_id, scenario, repair=False
        )
        reconcile.reconcile_validation_table(
            client,
            workspace_id,
            str(alert_case["id"]),
            scenario,
            repair=False,
        )
        integrations = reconcile.request_json(
            client, "GET", f"/workspaces/{workspace_id}/mcp-integrations"
        )
        matches = [
            row
            for row in integrations
            if isinstance(row, dict)
            and row.get("name") == reconcile.MCP_INTEGRATION_NAME
        ]
        require(
            len(matches) == 1, "managed Splunk MCP integration is missing or ambiguous"
        )
        desired = reconcile.desired_agent_preset(client, str(matches[0]["id"]))
        presets = reconcile.matching_agent_presets(client, workspace_id, desired)
        require(
            len(presets) == 1, "managed investigator preset is missing or ambiguous"
        )
        reconcile.verify_agent_preset(
            client, workspace_id, str(presets[0]["id"]), desired
        )
        grader = reconcile.desired_grader_preset(client, workspace_id)
        graders = reconcile.matching_agent_presets(client, workspace_id, grader)
        require(len(graders) == 1, "managed grader preset is missing or ambiguous")
        reconcile.verify_agent_preset(
            client, workspace_id, str(graders[0]["id"]), grader
        )
    print("Gym 001 repository and live integration checks passed.")
