"""Static integrity checks plus non-destructive health checks for Gym 003."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import tomllib

from . import config
from .policy import CURRENT_PROPOSAL_REVISION, render_modsecurity, validate_proposal


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _check_exact_dependencies() -> None:
    for path in config.ROOT.rglob("requirements*.txt"):
        for number, raw in enumerate(path.read_text().splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("--", "-r ", "-c ")):
                continue
            require(
                "==" in line and not re.search(r"(?:~=|>=|<=|!=|===|\*=)", line),
                f"dependency must use one exact == pin: {path.relative_to(config.ROOT)}:{number}",
            )
    for path in config.ROOT.rglob("pyproject.toml"):
        document = tomllib.loads(path.read_text())
        dependencies = list(document.get("project", {}).get("dependencies", []))
        dependencies.extend(document.get("build-system", {}).get("requires", []))
        for dependency in dependencies:
            require(
                "==" in dependency
                and not re.search(r"(?:~=|>=|<=|!=|===|\*=)", dependency),
                f"dependency must use one exact == pin: {path.relative_to(config.ROOT)}",
            )


def _check_lock() -> None:
    lock = config.load_lock()
    require(lock["gym"]["id"] == "003", "gym lock identity drifted")
    require(lock["gym"]["compose_project"] == config.PROJECT, "Compose project drifted")
    supply = lock.get("supply_chain", {})
    require(supply.get("image_cooldown_days") == 7, "image cooldown must be exactly seven days")
    require(supply.get("image_cooldown_cutoff") == "2026-08-30", "image cooldown cutoff drifted")
    for name, image in supply.get("verified_images", {}).items():
        require(image.get("digest", "").startswith("sha256:"), f"{name} is not digest pinned")
        require(image.get("official_source", "").startswith("https://"), f"{name} source is not official HTTPS")
        require("linux/arm64" in image.get("platforms", []), f"{name} lacks ARM64 provenance")
    local = lock["images"]["local"]["control"]
    require(local["input_sha256"] == config.image_input_hash(), "control image input hash is stale")
    template = config.ROOT / "assets/nuclei/CVE-2026-21858.yaml"
    expected = lock["sources"]["nuclei_template"]["sha256"]
    require(hashlib.sha256(template.read_bytes()).hexdigest() == expected, "pinned Nuclei template checksum drifted")


def _check_policy() -> None:
    proposal = {
        "scenario": "supplier-intake",
        "revision": CURRENT_PROPOSAL_REVISION,
        "route": "/form/supplier-intake",
        "method": "POST",
        "allowed_content_type": "multipart/form-data",
    }
    policy = validate_proposal(proposal, expected_revision=CURRENT_PROPOSAL_REVISION)
    for mode, expected_id in (("LOG_ONLY", 9300301), ("BLOCK", 9300302)):
        rule_id, rule = render_modsecurity(policy, mode)
        require(rule_id == expected_id and str(expected_id) in rule, f"{mode} rule ID drifted")
        require(
            "REQUEST_URI" in rule and "(?:[?].*)?" in rule and "multipart/form-data" in rule,
            f"{mode} predicate drifted",
        )
    try:
        validate_proposal(proposal | {"route": "/"}, expected_revision=CURRENT_PROPOSAL_REVISION)
    except ValueError:
        pass
    else:
        raise RuntimeError("policy accepted an unrestricted route")


def _check_compose() -> dict:
    merged = subprocess.run(
        config.compose_args("--profile", "bootstrap", "--profile", "evaluation", "config", "--format", "json"),
        cwd=config.ROOT,
        env=config.compose_environment(),
        text=True,
        capture_output=True,
    )
    require(merged.returncode == 0, f"Compose config failed: {merged.stderr}")
    document = json.loads(merged.stdout)
    services = document["services"]
    require("ports" not in services["n8n-target"], "n8n must not publish a host port")
    exposed = {
        (str(port.get("host_ip")), int(port.get("published")))
        for service in services.values()
        for port in service.get("ports", [])
    }
    require(exposed == {("127.0.0.1", 38080), ("127.0.0.1", 38081)}, f"unexpected host ports: {sorted(exposed)}")
    require("management" not in services["n8n-target"].get("networks", {}), "n8n reached management network")
    require("test-traffic" not in services["n8n-target"].get("networks", {}), "n8n reached test network")
    require("application" in services["n8n-target"].get("networks", {}), "n8n lacks application network")
    require("edge" in services["bunkerweb"].get("networks", {}), "BunkerWeb lacks its host-publishing edge network")
    require(services["caddy"].get("platform") == "linux/arm64", "Caddy must run the ARM64 child image")
    caddy_lock = config.load_lock()["supply_chain"]["verified_images"]["caddy"]
    require(
        services["caddy"].get("image", "").endswith(caddy_lock["platform_digest"]),
        "Caddy ARM64 child digest drifted",
    )
    n8n_env = services["n8n-target"].get("environment", {})
    require(
        not any("BUNKERWEB" in key or "TEST_API" in key for key in n8n_env),
        "vulnerable target received management credentials",
    )
    require(
        all("docker.sock" not in json.dumps(service.get("volumes", [])) for service in services.values()),
        "Docker socket exposure is forbidden",
    )
    require("test-api" not in services, "obsolete test API service is still present")
    executor = services["executor"]
    require(
        executor.get("image", "").startswith("tracecat-gyms/gym-003-control:"),
        "Tracecat executor must use the pinned Gym control image",
    )
    require(
        {"test-traffic", "management"} <= set(executor.get("networks", {})),
        "Tracecat executor lacks fixed target or firewall management access",
    )
    require(
        executor.get("environment", {}).get("TRACECAT__LOCAL_REPOSITORY_ENABLED")
        == "true",
        "Tracecat local registry must be enabled",
    )
    require(
        any(
            mount.get("target") == "/var/lib/gym"
            for mount in executor.get("volumes", [])
        ),
        "Tracecat executor lacks the shared operation state volume",
    )
    for name, service in services.items():
        image = service.get("image")
        if image and not image.startswith("tracecat-gyms/gym-003-control:"):
            require("@sha256:" in image, f"{name} image is not digest pinned: {image}")
    collector_mounts = services["waf-log-collector"].get("volumes", [])
    require(
        any(mount.get("read_only") is True for mount in collector_mounts if mount.get("target") == "/var/log/bunkerweb"),
        "WAF collector audit mount must be read-only",
    )
    audit_init_command = services["waf-audit-init"].get("command", [])
    if isinstance(audit_init_command, list):
        audit_init_command = " ".join(str(part) for part in audit_init_command)
    require(
        "if [ -L /var/log/bunkerweb/error.log ]; then rm /var/log/bunkerweb/error.log; fi" in audit_init_command
        and "if [ -L /var/log/bunkerweb/modsec_audit.log ]; then rm /var/log/bunkerweb/modsec_audit.log; fi" in audit_init_command
        and "touch /var/log/bunkerweb/error.log /var/log/bunkerweb/modsec_audit.log" in audit_init_command
        and "rm -f" not in audit_init_command,
        "WAF audit initializer must replace image symlinks without unlinking live log files",
    )
    require(
        "mkdir -p /var/lib/gym/jobs /var/lib/gym/state/supplier-intake"
        in audit_init_command
        and "chown -R 1001:1001 /var/lib/gym/jobs /var/lib/gym/state"
        in audit_init_command
        and "chmod 2770 /var/lib/gym/state /var/lib/gym/state/supplier-intake"
        in audit_init_command
        and "chmod 0660 /var/lib/gym/state/.operation.lock" in audit_init_command,
        "job and operation-lock directories must be writable by the control user",
    )
    require(
        services["eval-runner"].get("user") == f"{os.getuid()}:{os.getgid()}",
        "evaluation runner must use the invoking host user",
    )
    require(
        "1001" in services["eval-runner"].get("group_add", []),
        "evaluation runner must share the operation-lock group",
    )
    require(
        services["eval-runner"].get("environment", {}).get("HOME")
        == "/home/apiuser",
        "evaluation runner must give host UID tools a writable home",
    )
    require(
        any(
            str(item).startswith("/home/apiuser:")
            for item in services["eval-runner"].get("tmpfs", [])
        ),
        "evaluation runner must mount a writable scanner home",
    )
    return services


def _check_agent_boundary() -> None:
    scenario = json.loads((config.ROOT / "benchmark/scenario.json").read_text())
    require("expected_verdict" not in json.dumps(scenario), "agent context contains evaluation outcomes")
    for path in (config.ROOT / "benchmark/agent").rglob("*"):
        if path.is_file():
            text = path.read_text()
            require("BUNKERWEB_API_TOKEN" not in text, f"agent asset exposes firewall credentials: {path.name}")


def _check_live(services: dict) -> None:
    result = config.run_compose("ps", "--quiet", "api", capture=True, check=False)
    if not result.stdout.strip():
        print("[gym-003] static validation passed; stack is not running, so health checks were skipped")
        return
    for name in (
        "api", "n8n-target", "bunkerweb", "bw-api", "bw-scheduler",
        "waf-log-collector", "receipt-service", "minio",
    ):
        rows = config.run_compose("ps", "--quiet", name, capture=True).stdout.strip().splitlines()
        require(len(rows) == 1, f"running stack is missing {name}")
        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", rows[0]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        require(state == "running healthy", f"{name} is not healthy: {state}")
    executor_rows = config.run_compose(
        "ps", "--quiet", "executor", capture=True
    ).stdout.strip().splitlines()
    require(len(executor_rows) == 1, "running stack is missing executor")
    executor_state = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", executor_rows[0]],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    require(executor_state == "running", f"executor is not running: {executor_state}")
    for port in (38080, 38081):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                pass
        except OSError as exc:
            raise RuntimeError(f"loopback port {port} is not reachable") from exc
    print("[gym-003] repository and live health validation passed")


def validate() -> None:
    _check_exact_dependencies()
    _check_lock()
    _check_policy()
    services = _check_compose()
    _check_agent_boundary()
    _check_live(services)
