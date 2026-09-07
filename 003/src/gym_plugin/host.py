"""Host lifecycle for Gym 003."""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
from datetime import UTC, date, datetime
from pathlib import Path

from gymctl import lifecycle

from . import config


class GymError(lifecycle.LifecycleError):
    pass


def log(message: str) -> None:
    print(f"[gym-003] {message}", flush=True)


def run(command: list[str], *, check: bool = True, capture: bool = False):
    return lifecycle.run(config.ROOT, command, check=check, capture=capture)


def init() -> None:
    target = config.ROOT / ".env"
    if target.exists():
        target.chmod(0o600)
        log("Existing .env retained; credentials were not rotated.")
        return
    replacements = {
        "TRACECAT__DB_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "TRACECAT__SERVICE_KEY": secrets.token_hex(32),
        "TRACECAT__SIGNING_SECRET": secrets.token_hex(32),
        "USER_AUTH_SECRET": secrets.token_hex(32),
        "TRACECAT__POSTGRES_PASSWORD": secrets.token_hex(24),
        "TEMPORAL__POSTGRES_PASSWORD": secrets.token_hex(24),
        "MINIO_ROOT_PASSWORD": secrets.token_hex(24),
        "TRACEcat_TENANT_PASSWORD": secrets.token_urlsafe(24),
        "TRACEcat_SUPERADMIN_PASSWORD": secrets.token_urlsafe(24),
        "GYM_TEST_API_TOKEN": secrets.token_urlsafe(32),
        "BUNKERWEB_API_TOKEN": secrets.token_urlsafe(32),
        "BUNKERWEB_DB_PASSWORD": secrets.token_urlsafe(24),
        "GYM_N8N_STAFF_PASSWORD": "Gym003-" + secrets.token_urlsafe(18),
        "N8N_ENCRYPTION_KEY": secrets.token_hex(32),
    }
    lifecycle.write_env(config.DEFINITION, replacements)
    log("Created .env with random credentials and mode 0600.")


def _check_ports() -> None:
    for port in (38080, 38081):
        rows = run(
            ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.ID}}"],
            capture=True,
        ).stdout.split()
        for container in rows:
            owner = run(
                ["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}', container],
                capture=True,
            ).stdout.strip()
            if owner != config.PROJECT:
                raise GymError(f"port {port} belongs to Docker project {owner or 'unknown'}")
        if not rows:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    raise GymError(f"host port {port} is occupied")


def _verify_cooldown_lock() -> None:
    lock = config.load_lock()
    cutoff = date.fromisoformat(lock["supply_chain"]["image_cooldown_cutoff"])
    if cutoff > date.today():
        raise GymError("image cooldown cutoff is in the future")
    records = lock["supply_chain"]["verified_images"]
    if not records:
        raise GymError("no verified image provenance records")
    for name, item in records.items():
        if not item.get("official_source", "").startswith("https://"):
            raise GymError(f"{name} lacks an official HTTPS source")
        cooldown_complete = datetime.fromisoformat(
            item["cooldown_complete_at"].replace("Z", "+00:00")
        )
        if (
            date.fromisoformat(item["published_at"][:10]) > cutoff
            and datetime.now(UTC) < cooldown_complete
        ):
            reference = f"{item['source_ref']}@{item['digest']}"
            present = run(["docker", "image", "inspect", reference], check=False, capture=True)
            if present.returncode != 0:
                raise GymError(
                    f"{name} is still cooling down and is not already local; "
                    f"do not download it before {item['cooldown_complete_at']}"
                )
        if not str(item.get("digest", "")).startswith("sha256:"):
            raise GymError(f"{name} is not pinned by digest")
        if "linux/arm64" not in item.get("platforms", []):
            raise GymError(f"{name} has no verified ARM64-compatible image")


def doctor() -> None:
    for name in ("docker", "git", "just"):
        if shutil.which(name) is None:
            raise GymError(f"required command is missing: {name}")
    architecture = run(["docker", "info", "--format", "{{.Architecture}}"], capture=True).stdout.strip()
    if architecture not in {"aarch64", "arm64"}:
        raise GymError(f"Gym 003 lock is currently validated only for ARM64, got {architecture}")
    _verify_cooldown_lock()
    _check_ports()
    log("Doctor passed: ARM64 and locked image cooldown provenance verified.")


def build(components: tuple[str, ...] = (), *, force: bool = False) -> None:
    if components and components != ("control",):
        raise GymError("Gym 003 build accepts only the control component")
    digest = config.image_input_hash()
    image = config.local_image()
    if not force and lifecycle.image_label(config.ROOT, image, "org.tracecat.gym.input-sha") == digest:
        log(f"control image is current: {image}")
        return
    revision = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    lifecycle.build_image(
        config.DEFINITION,
        image=image,
        dockerfile=config.ROOT / "images/control/Dockerfile",
        context=config.ROOT,
        input_digest=digest,
        build_contexts={"gymctl": config.REPO_ROOT / "src/gymctl"},
        build_args={
            "TRACECAT_IMAGE": config.upstream_image("tracecat"),
            "TRACECAT_VERSION": config.load_platform_lock()["tracecat"]["tag"],
            "GYM_COMPONENT_VERSION": config.load_lock()["gym"]["component_version"],
            "GYM_INPUT_SHA": digest,
            "GYM_REVISION": revision,
        },
        force=True,
    )


def _run_bootstrap(service: str, timeout: int = 900) -> None:
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, service, timeout=timeout)


def _wait_health(timeout: int = 900) -> None:
    required = (
        "api", "litellm", "postgres_db", "temporal", "minio", "redis",
        "n8n-target", "bunkerweb", "bw-api", "bw-scheduler", "waf-log-collector",
        "test-api", "receipt-service",
    )
    lifecycle.wait_runtime_health(
        config.DEFINITION,
        config.run_compose,
        required,
        timeout=timeout,
        on_change=lambda states: log("waiting: " + ", ".join(f"{k}={v}" for k, v in states.items() if v != "running healthy")),
    )


def up() -> None:
    init()
    doctor()
    build()
    # `doctor` rejects any absent image that has not completed its cooldown.
    # Compose may therefore fetch only old-enough, digest-pinned images here.
    config.run_compose("up", "--detach")
    _wait_health()
    _run_bootstrap("target-seed", 300)
    _run_bootstrap("tracecat-seed", 600)
    _run_bootstrap("gym-reconciler", 600)
    info()


def info() -> None:
    env = config.parse_env()
    if not env:
        raise GymError(".env is missing; run just init")
    print("Tracecat UI: http://127.0.0.1:38080")
    print("Protected supplier intake: http://127.0.0.1:38081 (Host: supplier.intake.test)")
    print(f"Tenant: {env['TRACEcat_TENANT_EMAIL']} / {env['TRACEcat_TENANT_PASSWORD']}")


def status() -> None:
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "ps", "--all", check=False)
    if not lifecycle.container_id(config.run_compose, "api"):
        raise GymError("Gym 003 is not running")
    result = config.run_compose(
        "--profile",
        "bootstrap",
        "run",
        "--rm",
        "--no-deps",
        "gym-reconciler",
        "internal-reconcile",
        "status",
        check=False,
    )
    if result.returncode:
        raise GymError("Gym 003 reconciliation status failed")


def wait() -> None:
    _wait_health()
    container = lifecycle.container_id(config.run_compose, "gym-reconciler")
    if not container:
        raise GymError("gym reconciler has not run")
    lifecycle.wait_exit(config.DEFINITION, config.run_compose, "gym-reconciler", timeout=600)
    status()
    log("Full Gym 003 readiness checks passed.")


def reconcile() -> None:
    build()
    _run_bootstrap("target-seed", 300)
    _run_bootstrap("tracecat-seed", 600)
    _run_bootstrap("gym-reconciler", 600)


def evaluate() -> int:
    wait()
    results = config.ROOT / "eval-results"
    lifecycle.ensure_host_directory(results)
    return config.run_compose(
        "--profile", "evaluation", "run", "--rm", "--no-deps", "eval-runner", "internal-eval",
        check=False,
    ).returncode


def logs(service: str | None) -> None:
    args = ["--profile", "bootstrap", "--profile", "evaluation", "logs", "--follow", "--tail", "200"]
    if service:
        args.append(service)
    config.run_compose(*args)


def down() -> None:
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "down", "--remove-orphans")
    log("Stopped; volumes, rule state, and evidence retained.")


def restart() -> None:
    down()
    up()


def internal_scenario_reset() -> None:
    from .operation_lock import exclusive_operation
    from .probe import reset_probe_state
    from .waf import WAFClient
    ctx = {
        "scenario": "supplier-intake",
        "evidence_dir": Path("/var/lib/gym/jobs/reset"),
        "state_dir": Path("/var/lib/gym/state"),
    }
    with exclusive_operation(ctx["state_dir"]):
        probe = reset_probe_state(ctx)
        waf = WAFClient.from_env().restore({"configs": []})
    print(json.dumps({"probe": probe, "waf": waf}, sort_keys=True))


def scenario_reset(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError("scenario-reset changes target and firewall state; rerun as `just scenario-reset CONFIRM=artifacts-captured`")
    config.run_compose("run", "--rm", "--no-deps", "test-api", "internal-scenario-reset")
    log("Removed managed rules and probe artifacts; retained evidence.")


def reset(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError("reset destroys Gym 003 state; rerun as `just reset CONFIRM=artifacts-captured`")
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "down", "--volumes", "--remove-orphans")
    log("Removed Gym 003 containers and volumes; host eval-results retained.")


def clean_restart(confirm: str | None) -> None:
    reset(confirm)
    up()


def migrate() -> None:
    log("Gym 003 has no legacy volume namespace; no migration is required.")


def check_upstreams() -> None:
    from gymctl.update_upstreams import check_upstreams
    check_upstreams()


def update_upstreams() -> None:
    from gymctl.update_upstreams import update_upstreams as update
    update()


def volume_digest(path: Path) -> str:
    return lifecycle.volume_digest(path)
