"""Host-side lifecycle for Gym 002. Standard-library only."""

from __future__ import annotations
import base64
import os
import secrets
import shutil
import socket
from pathlib import Path

from gymctl import lifecycle

from . import config


class GymError(lifecycle.LifecycleError):
    pass


def log(message: str) -> None:
    print(f"[gym-002] {message}", flush=True)


def run(command: list[str], *, check: bool = True, capture: bool = False):
    return lifecycle.run(config.ROOT, command, check=check, capture=capture)


def init() -> None:
    target = config.ROOT / ".env"
    if target.exists():
        target.chmod(0o600)
        log("Existing .env retained; credentials were not rotated.")
        return
    replacements = {
        "TRACECAT__DB_ENCRYPTION_KEY": base64.urlsafe_b64encode(
            os.urandom(32)
        ).decode(),
        "TRACECAT__SERVICE_KEY": secrets.token_hex(32),
        "TRACECAT__SIGNING_SECRET": secrets.token_hex(32),
        "USER_AUTH_SECRET": secrets.token_hex(32),
        "TRACECAT__POSTGRES_PASSWORD": secrets.token_hex(24),
        "TEMPORAL__POSTGRES_PASSWORD": secrets.token_hex(24),
        "MINIO_ROOT_PASSWORD": secrets.token_hex(24),
        "TRACEcat_TENANT_PASSWORD": secrets.token_urlsafe(24),
        "TRACEcat_SUPERADMIN_PASSWORD": secrets.token_urlsafe(24),
    }
    lifecycle.write_env(config.DEFINITION, replacements)
    log("Created .env with random credentials and mode 0600.")


def doctor() -> None:
    for name in ("docker", "git", "git-lfs", "just"):
        if shutil.which(name) is None:
            raise GymError(f"required command is missing: {name}")
    run(["docker", "info"], capture=True)
    port = config.DEFINITION.host_port
    rows = run(
        ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.ID}}"],
        capture=True,
    ).stdout.split()
    for container in rows:
        owner = run(
            [
                "docker",
                "inspect",
                "--format",
                '{{index .Config.Labels "com.docker.compose.project"}}',
                container,
            ],
            capture=True,
        ).stdout.strip()
        if owner != config.PROJECT:
            raise GymError(
                f"port {port} belongs to Docker project {owner or 'unknown'}"
            )
    if not rows:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise GymError(f"host port {port} is occupied")
    from .dataset import validate_archive

    validate_archive()
    attr = run(
        [
            "git",
            "-C",
            str(config.ROOT.parent),
            "check-attr",
            "filter",
            "--",
            "002/assets/botsv3-20260904T130332Z-1-001.zip",
        ],
        capture=True,
    ).stdout
    if not attr.rstrip().endswith(": lfs"):
        raise GymError("BOTSv3 archive is not tracked by Git LFS")
    log("Doctor passed.")


def _image_label(image: str) -> str | None:
    return lifecycle.image_label(config.ROOT, image, "org.tracecat.gym.input-sha")


def build(*, force: bool = False) -> None:
    digest = config.image_input_hash()
    image = config.local_image()
    if not force and _image_label(image) == digest:
        log(f"control image is current: {image}")
        return
    revision = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    lock = config.load_lock()
    platform = config.load_platform_lock()
    lifecycle.build_image(
        config.DEFINITION,
        image=image,
        dockerfile=config.ROOT / "images/control/Dockerfile",
        context=config.ROOT,
        input_digest=digest,
        build_contexts={"gymctl": config.REPO_ROOT / "src/gymctl"},
        build_args={
            "TRACECAT_IMAGE": config.upstream_image("tracecat"),
            "TRACECAT_VERSION": platform["tracecat"]["tag"],
            "GYM_COMPONENT_VERSION": lock["gym"]["component_version"],
            "GYM_INPUT_SHA": digest,
            "GYM_REVISION": revision,
        },
        force=True,
    )


def _container_id(service: str) -> str:
    return lifecycle.container_id(config.run_compose, service)


def _wait_exit(service: str, timeout: int = 900) -> None:
    lifecycle.wait_exit(
        config.DEFINITION,
        config.run_compose,
        service,
        timeout=timeout,
    )


def _run_bootstrap(service: str, timeout: int = 900) -> None:
    lifecycle.run_bootstrap(
        config.DEFINITION,
        config.run_compose,
        service,
        timeout=timeout,
    )


def _wait_runtime_health(timeout: int = 600) -> None:
    required = ("api", "litellm", "postgres_db", "temporal", "minio", "redis")
    lifecycle.wait_runtime_health(
        config.DEFINITION,
        config.run_compose,
        required,
        timeout=timeout,
        on_change=lambda states: log(
            "waiting for runtime health: "
            + ", ".join(
                f"{key}={value}"
                for key, value in states.items()
                if value != "running healthy"
            )
        ),
    )


def up() -> None:
    init()
    doctor()
    build()
    config.run_compose("up", "--detach")
    _run_bootstrap("dataset-seed", 1200)
    _run_bootstrap("tracecat-seed", 600)
    _run_bootstrap("gym-reconciler", 600)
    info()


def info() -> None:
    env = config.parse_env()
    if not env:
        raise GymError(".env is missing; run just init")
    print(f"Tracecat UI: http://127.0.0.1:{config.DEFINITION.host_port}")
    print(
        f"  Tenant: {env['TRACEcat_TENANT_EMAIL']} / {env['TRACEcat_TENANT_PASSWORD']}"
    )
    print(
        f"  Superadmin: {env['TRACEcat_SUPERADMIN_EMAIL']} / {env['TRACEcat_SUPERADMIN_PASSWORD']}"
    )


def status() -> None:
    config.run_compose("--profile", "bootstrap", "ps", "--all", check=False)
    if not _container_id("api"):
        raise GymError("Gym 002 is not running")
    env = config.parse_env()
    from gymctl.http import Client
    from . import reconcile as state

    with Client(
        base_url=env["PUBLIC_API_URL"], timeout=120, follow_redirects=True
    ) as client:
        state.status(
            client,
            env["TRACEcat_TENANT_EMAIL"],
            env["TRACEcat_TENANT_PASSWORD"],
        )


def reconcile() -> None:
    build()
    _run_bootstrap("dataset-seed", 1200)
    _run_bootstrap("tracecat-seed", 600)
    _run_bootstrap("gym-reconciler", 600)


def wait() -> None:
    container = _container_id("gym-reconciler")
    if not container:
        raise GymError("gym reconciler has not run; run just up or just reconcile")
    _wait_exit("gym-reconciler", 600)
    _wait_runtime_health()
    status()
    log("Full Gym 002 readiness checks passed.")


def migrate() -> None:
    log("Gym 002 has no legacy volume namespace; no migration is required.")


def evaluate(alert_id: str | None = None, *, via_workflow: bool = False) -> int:
    wait()
    build()
    results = config.ROOT / "eval-results"
    lifecycle.ensure_host_directory(results)
    command = [
        "--profile",
        "evaluation",
        "run",
        "--rm",
        "--no-deps",
        "eval-runner",
        "internal-eval",
    ]
    if alert_id:
        command += ["--alert-id", alert_id]
    if via_workflow:
        command.append("--via-workflow")
    return config.run_compose(*command, check=False).returncode


def rescore(eval_id: str, alert_id: str | None = None) -> int:
    """Re-score a completed evaluation without re-running investigators."""
    build()
    results = config.ROOT / "eval-results"
    if not (results / eval_id).is_dir():
        raise GymError(f"evaluation {eval_id} not found under {results}")
    command = [
        "--profile",
        "evaluation",
        "run",
        "--rm",
        "--no-deps",
        "eval-runner",
        "internal-rescore",
        "--eval-id",
        eval_id,
    ]
    if alert_id:
        command += ["--alert-id", alert_id]
    return config.run_compose(*command, check=False).returncode


def logs(service: str | None) -> None:
    args = ["--profile", "bootstrap", "logs", "--follow", "--tail", "200"]
    if service:
        args.append(service)
    config.run_compose(*args)


def down() -> None:
    config.run_compose(
        "--profile", "bootstrap", "--profile", "evaluation", "down", "--remove-orphans"
    )
    log("Stopped; volumes and credentials retained.")


def reset(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError(
            "reset destroys Gym 002 state; rerun only after preserving artifacts as `just reset CONFIRM=artifacts-captured`"
        )
    config.run_compose(
        "--profile",
        "bootstrap",
        "--profile",
        "evaluation",
        "down",
        "--volumes",
        "--remove-orphans",
    )
    log(
        "Removed only tracecat-gym-002 containers and volumes; host eval-results were retained."
    )


def clean_restart(confirm: str | None) -> None:
    reset(confirm)
    up()


def reset_evals(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError(
            "reset-evals deletes managed cases and sessions; rerun only after preserving artifacts as `just reset-evals CONFIRM=artifacts-captured`"
        )
    build()
    config.run_compose(
        "--profile",
        "bootstrap",
        "run",
        "--rm",
        "--no-deps",
        "gym-reconciler",
        "internal-reset-evals",
    )


def check_upstreams() -> None:
    from gymctl.update_upstreams import check_upstreams as check

    check()


def update_dataset(args) -> None:
    unsupported = {
        "--ref": args.ref,
        "--writeup-html": args.writeup_html,
        "--duckdb": args.duckdb,
        "--data-glob": args.data_glob,
    }
    used = [name for name, value in unsupported.items() if value is not None]
    if used:
        raise GymError(f"Gym 002 update-dataset does not accept: {', '.join(used)}")
    command = ["python3", str(config.ROOT / "tools/update_dataset.py")]
    if args.archive is not None:
        command += ["--archive", str(args.archive)]
    run(command)


def volume_digest(path: Path) -> str:
    return lifecycle.volume_digest(path)
