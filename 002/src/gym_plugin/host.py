"""Host-side lifecycle for Gym 002. Standard-library only."""

from __future__ import annotations
import base64
import hashlib
import os
import secrets
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from . import config


class GymError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gym-002] {message}", flush=True)


def run(command: list[str], *, check: bool = True, capture: bool = False):
    return subprocess.run(
        command, cwd=config.ROOT, check=check, text=True, capture_output=capture
    )


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
    output = []
    sources = (
        config.REPO_ROOT / "config/tracecat.env.example",
        config.ROOT / ".env.example",
    )
    for line in "\n".join(
        source.read_text().rstrip() for source in sources
    ).splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in replacements:
            line = f"{key}={replacements[key]}"
        elif key == "TRACECAT__DB_URI":
            line = f"TRACECAT__DB_URI=postgresql+psycopg://postgres:{replacements['TRACECAT__POSTGRES_PASSWORD']}@postgres_db:5432/postgres"
        output.append(line)
    temporary = config.ROOT / f".env.tmp.{os.getpid()}"
    old = os.umask(0o077)
    try:
        temporary.write_text("\n".join(output) + "\n")
        temporary.replace(target)
    finally:
        os.umask(old)
    target.chmod(0o600)
    log("Created .env with random credentials and mode 0600.")


def doctor() -> None:
    for name in ("docker", "git", "git-lfs", "just"):
        if shutil.which(name) is None:
            raise GymError(f"required command is missing: {name}")
    run(["docker", "info"], capture=True)
    rows = run(
        ["docker", "ps", "--filter", "publish=28080", "--format", "{{.ID}}"],
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
            raise GymError(f"port 28080 belongs to Docker project {owner or 'unknown'}")
    if not rows:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 28080)) == 0:
                raise GymError("host port 28080 is occupied")
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
    result = run(
        [
            "docker",
            "image",
            "inspect",
            image,
            "--format",
            '{{index .Config.Labels "org.tracecat.gym.input-sha"}}',
        ],
        check=False,
        capture=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def build(*, force: bool = False) -> None:
    digest = config.image_input_hash()
    image = config.local_image()
    if not force and _image_label(image) == digest:
        log(f"control image is current: {image}")
        return
    revision = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    lock = config.load_lock()
    platform = config.load_platform_lock()
    run(
        [
            "docker",
            "build",
            "--file",
            str(config.ROOT / "images/control/Dockerfile"),
            "--tag",
            image,
            "--build-context",
            f"gymctl={config.REPO_ROOT / 'src/gymctl'}",
            "--build-arg",
            f"TRACECAT_IMAGE={config.upstream_image('tracecat')}",
            "--build-arg",
            f"TRACECAT_VERSION={platform['tracecat']['tag']}",
            "--build-arg",
            f"GYM_COMPONENT_VERSION={lock['gym']['component_version']}",
            "--build-arg",
            f"GYM_INPUT_SHA={digest}",
            "--build-arg",
            f"GYM_REVISION={revision}",
            str(config.ROOT),
        ]
    )
    if _image_label(image) != digest:
        raise GymError("built control image label mismatch")


def _container_id(service: str) -> str:
    rows = (
        config.run_compose(
            "--profile", "bootstrap", "ps", "--all", "--quiet", service, capture=True
        )
        .stdout.strip()
        .splitlines()
    )
    return rows[0] if rows else ""


def _wait_exit(service: str, timeout: int = 900) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container = _container_id(service)
        if container:
            state = run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}} {{.State.ExitCode}}",
                    container,
                ],
                capture=True,
            ).stdout.strip()
            if state.startswith("exited "):
                if state != "exited 0":
                    config.run_compose(
                        "--profile",
                        "bootstrap",
                        "logs",
                        "--no-color",
                        service,
                        check=False,
                    )
                    raise GymError(f"{service} failed: {state}")
                return
        time.sleep(2)
    raise GymError(f"timed out waiting for {service}")


def _run_bootstrap(service: str, timeout: int = 900) -> None:
    config.run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        service,
    )
    _wait_exit(service, timeout)


def _wait_runtime_health(timeout: int = 600) -> None:
    required = ("api", "litellm", "postgres_db", "temporal", "minio", "redis")
    deadline = time.monotonic() + timeout
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        states: dict[str, str] = {}
        for service in required:
            container = _container_id(service)
            if not container:
                states[service] = "missing"
                continue
            states[service] = run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    container,
                ],
                capture=True,
            ).stdout.strip()
        if all(value == "running healthy" for value in states.values()):
            return
        if states != last:
            log(
                "waiting for runtime health: "
                + ", ".join(
                    f"{key}={value}"
                    for key, value in states.items()
                    if value != "running healthy"
                )
            )
            last = states
        time.sleep(5)
    raise GymError(f"services did not become healthy: {last}")


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
    print("Tracecat UI: http://127.0.0.1:28080")
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

    with Client(base_url=env["PUBLIC_API_URL"], timeout=120) as client:
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


def evaluate(alert_id: str | None = None) -> None:
    wait()
    build()
    results = config.ROOT / "eval-results"
    results.mkdir(mode=0o700, exist_ok=True)
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
    config.run_compose(*command)


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
    if args.ref:
        raise GymError("Gym 002 update-dataset does not accept --ref")
    command = ["python3", str(config.ROOT / "tools/update_dataset.py")]
    for option, value in (
        ("--writeup-html", args.writeup_html),
        ("--duckdb", args.duckdb),
        ("--data-glob", args.data_glob),
        ("--archive", args.archive),
    ):
        if value is not None:
            command += [option, str(value)]
    run(command)


def volume_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(
        path.rglob("*"), key=lambda value: value.relative_to(path).as_posix()
    ):
        details = item.lstat()
        relative = item.relative_to(path).as_posix()
        if item.is_symlink():
            kind, payload = "L", os.readlink(item).encode()
        elif item.is_dir():
            kind, payload = "D", b""
        elif item.is_file():
            kind, payload = "F", item.read_bytes()
        else:
            kind, payload = "O", b""
        digest.update(
            f"{relative}\0{kind}\0{stat.S_IMODE(details.st_mode):o}\0{details.st_uid}\0{details.st_gid}\0".encode()
        )
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()
