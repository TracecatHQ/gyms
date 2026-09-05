"""Host-side lifecycle for Gym 001. Standard-library only."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from gymctl import lifecycle

from . import config
from .license import load_metadata, validate_current


class GymError(lifecycle.LifecycleError):
    pass


def log(message: str) -> None:
    print(f"[gym-001] {message}", flush=True)


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
):
    return lifecycle.run(config.ROOT, command, check=check, capture=capture, env=env)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def docker_volume_exists(name: str) -> bool:
    return (
        subprocess.run(
            ["docker", "volume", "inspect", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def validate_license(
    *, expected: bool = True, path: Path | None = None
) -> dict[str, object]:
    license_path = path or config.ROOT / "assets/Splunk.License"
    metadata = load_metadata(license_path)
    expected_sha = None
    if expected:
        expected_sha = config.load_lock()["artifacts"]["splunk_license"]["sha256"]
    validate_current(metadata, expected_sha)
    return metadata


def init_env() -> None:
    target = config.ROOT / ".env"
    if target.exists():
        target.chmod(0o600)
        if config.parse_env(target).get("SPLUNK_ACCEPT_TERMS") != "yes":
            raise GymError(
                "Existing .env does not record Splunk terms acceptance. Review "
                "https://www.splunk.com/en_us/legal/splunk-general-terms.html"
            )
        log("Existing .env retained; credentials were not rotated.")
        validate_license()
        return
    if os.environ.get("SPLUNK_ACCEPT_TERMS") != "yes":
        raise GymError(
            "Splunk terms acceptance is required. Review "
            "https://www.splunk.com/en_us/legal/splunk-general-terms.html then run "
            "SPLUNK_ACCEPT_TERMS=yes just up"
        )
    replacements = {
        "TRACECAT__DB_ENCRYPTION_KEY": secrets.token_urlsafe(32),
        "TRACECAT__SERVICE_KEY": secrets.token_hex(32),
        "TRACECAT__SIGNING_SECRET": secrets.token_hex(32),
        "USER_AUTH_SECRET": secrets.token_hex(32),
        "TRACECAT__POSTGRES_PASSWORD": secrets.token_hex(24),
        "TEMPORAL__POSTGRES_PASSWORD": secrets.token_hex(24),
        "MINIO_ROOT_PASSWORD": secrets.token_hex(24),
        "TRACEcat_TENANT_PASSWORD": secrets.token_urlsafe(24),
        "TRACEcat_SUPERADMIN_PASSWORD": secrets.token_urlsafe(24),
        "SPLUNK_ADMIN_PASSWORD": f"Sp1-{secrets.token_hex(24)}",
        "SPLUNK_MCP_PASSWORD": f"Mc2-{secrets.token_hex(24)}",
    }
    lifecycle.write_env(config.DEFINITION, replacements)
    log("Created .env with random credentials and mode 0600.")
    validate_license()


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(item) for item in re.findall(r"\d+", value)[:3])


def doctor(*, allow_legacy_ports: bool = False) -> None:
    for name in ("docker", "git", "just", "curl", "openssl"):
        if not command_exists(name):
            raise GymError(f"required command is missing: {name}")
    run(["docker", "info"], capture=True)
    version = (
        run(["docker", "compose", "version", "--short"], capture=True)
        .stdout.strip()
        .lstrip("v")
    )
    if _version_tuple(version) < (2, 24, 4):
        raise GymError(f"Docker Compose {version} is too old; 2.24.4+ is required")
    available = shutil.disk_usage(config.ROOT).free
    if available < 30 * 1024**3:
        raise GymError(
            f"30 GiB free disk is required; {available / 1024**3:.1f} GiB is available. Nothing was pruned."
        )
    if run(
        [
            "git",
            "-C",
            str(config.ROOT.parent),
            "submodule",
            "status",
            "--",
            "001/upstream/dataset",
        ],
        capture=True,
    ).stdout.startswith("-"):
        raise GymError(
            "dataset submodule is missing; run git submodule update --init --recursive"
        )
    lock = config.load_lock()
    head = run(
        ["git", "-C", str(config.ROOT / "upstream/dataset"), "rev-parse", "HEAD"],
        capture=True,
    ).stdout.strip()
    if head != lock["sources"]["dataset"]["commit"]:
        raise GymError(
            f"dataset submodule is at {head}, expected {lock['sources']['dataset']['commit']}"
        )
    env = config.parse_env()
    if env.get("SPLUNK_ACCEPT_TERMS") != "yes":
        raise GymError("Splunk terms acceptance is not recorded in .env")
    for port in (config.DEFINITION.host_port, 18000):
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
            allowed = {config.PROJECT}
            if allow_legacy_ports:
                allowed.add(config.LEGACY_PROJECT)
            if owner not in allowed:
                raise GymError(
                    f"port {port} belongs to Docker project {owner or 'unknown'} ({container})"
                )
        if not rows:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    raise GymError(
                        f"host port {port} is already occupied outside this gym"
                    )
    validate_license()
    if os.uname().machine == "arm64":
        log("Splunk is amd64-only; Docker emulation will be used on Apple Silicon.")
        run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "/bin/true",
                config.upstream_image("splunk"),
            ]
        )
        log(
            "Splunk 10.4's AVX installer probe is bypassed because translated containers cannot expose AVX; legacy migration volumes remain rollback-safe."
        )
    log(f"Doctor passed: Compose {version}; {available / 1024**3:.1f} GiB free.")


def check_upstreams() -> None:
    from gymctl.update_upstreams import check_upstreams as check

    check(config.load_lock()["images"].get("upstream", {}))


def _image_label(image: str, key: str) -> str | None:
    return lifecycle.image_label(config.ROOT, image, key)


def build(
    components: tuple[str, ...] = ("splunk", "control"), *, force: bool = False
) -> None:
    lock = config.load_lock()
    platform = config.load_platform_lock()
    revision = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    for component in components:
        digest = config.image_input_hash(component)
        image = config.local_image(component)
        if not force and _image_label(image, "org.tracecat.gym.input-sha") == digest:
            log(f"{component} image is current: {image}")
            continue
        command = [
            "docker",
            "build",
            "--file",
            str(config.ROOT / f"images/{component}/Dockerfile"),
            "--tag",
            image,
        ]
        if component == "splunk":
            command += [
                "--platform",
                "linux/amd64",
                "--build-arg",
                f"SPLUNK_IMAGE={config.upstream_image('splunk')}",
                "--build-arg",
                f"DATASET_COMMIT={lock['sources']['dataset']['commit']}",
                "--build-arg",
                "SPLUNK_VERSION=10.4.1",
                "--build-arg",
                f"MCP_VERSION={lock['artifacts']['splunk_mcp']['version']}",
            ]
        else:
            command += [
                "--build-context",
                f"gymctl={config.REPO_ROOT / 'src/gymctl'}",
                "--build-arg",
                f"TRACECAT_IMAGE={config.upstream_image('tracecat')}",
                "--build-arg",
                f"TRACECAT_VERSION={platform['tracecat']['tag']}",
            ]
        command += [
            "--build-arg",
            f"GYM_COMPONENT_VERSION={lock['gym']['component_version']}",
            "--build-arg",
            f"GYM_INPUT_SHA={digest}",
            "--build-arg",
            f"GYM_REVISION={revision}",
            str(config.ROOT),
        ]
        log(f"Building {component} image {image}...")
        run(command)
        observed = _image_label(image, "org.tracecat.gym.input-sha")
        if observed != digest:
            raise GymError(
                f"built {component} image label mismatch: expected {digest}, got {observed}"
            )


def _container_id(service: str, profile: str | None = None) -> str:
    return lifecycle.container_id(config.run_compose, service, profile=profile)


def _wait_exit(service: str, timeout: int, profile: str = "bootstrap") -> None:
    lifecycle.wait_exit(
        config.DEFINITION,
        config.run_compose,
        service,
        timeout=timeout,
        profile=profile,
    )


def _start_stack() -> None:
    config.run_compose("up", "--detach")
    config.run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "tracecat-seed",
    )
    _wait_exit("tracecat-seed", 600)
    config.run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "gym-reconciler",
    )
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{config.DEFINITION.host_port}/api/health",
                timeout=5,
            ) as response:
                if response.status == 200:
                    log(
                        "Tracecat is ready; Splunk reconciliation continues asynchronously."
                    )
                    info()
                    return
        except Exception:
            time.sleep(3)
    raise GymError("Tracecat did not become ready within 10 minutes")


def up(*, allow_fresh_with_legacy: bool = False) -> None:
    init_env()
    doctor(allow_legacy_ports=False)
    check_upstreams()
    new = [
        docker_volume_exists(config.volume_name(config.PROJECT, suffix))
        for suffix in config.VOLUME_SUFFIXES
    ]
    legacy = [
        docker_volume_exists(config.volume_name(config.LEGACY_PROJECT, suffix))
        for suffix in config.VOLUME_SUFFIXES
    ]
    if any(legacy) and not any(new) and not allow_fresh_with_legacy:
        raise GymError(
            "legacy The Bigger Interview volumes exist while Gym 001 volumes do not; run `just migrate` to preserve state"
        )
    build()
    _start_stack()


def info() -> None:
    env = config.parse_env()
    if not env:
        raise GymError(".env is missing; run SPLUNK_ACCEPT_TERMS=yes just up")
    print(f"Tracecat UI: http://127.0.0.1:{config.DEFINITION.host_port}")
    print(
        f"  Tenant: {env['TRACEcat_TENANT_EMAIL']} / {env['TRACEcat_TENANT_PASSWORD']}"
    )
    print(
        f"  Superadmin: {env['TRACEcat_SUPERADMIN_EMAIL']} / {env['TRACEcat_SUPERADMIN_PASSWORD']}"
    )
    print("Splunk UI: http://127.0.0.1:18000")
    print(f"  Admin: {env['SPLUNK_ADMIN_USER']} / {env['SPLUNK_ADMIN_PASSWORD']}")


def status() -> None:
    validate_license()
    config.run_compose("--profile", "bootstrap", "ps", "--all", check=False)
    if not _container_id("api"):
        raise GymError("Gym 001 is not running")
    config.run_compose(
        "--profile",
        "bootstrap",
        "run",
        "--rm",
        "--no-deps",
        "gym-reconciler",
        "internal-reconcile",
        "status",
    )


def wait() -> None:
    container = _container_id("gym-reconciler", "bootstrap")
    if not container:
        raise GymError("gym reconciler is not running; run just up or just reconcile")
    last = 0.0
    while True:
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
            config.run_compose(
                "--profile",
                "bootstrap",
                "logs",
                "--no-color",
                "gym-reconciler",
                check=False,
            )
            if state != "exited 0":
                raise GymError(f"gym reconciliation failed: {state}")
            _wait_runtime_health(600)
            status()
            log("Full Gym 001 readiness checks passed.")
            return
        if time.monotonic() - last > 30:
            run(["docker", "logs", "--tail", "1", container], check=False)
            last = time.monotonic()
        time.sleep(5)


def _wait_runtime_health(timeout: int) -> None:
    required = (
        "api",
        "litellm",
        "postgres_db",
        "temporal",
        "minio",
        "redis",
        "splunk",
        "splunk-mcp-compat",
    )
    lifecycle.wait_runtime_health(
        config.DEFINITION,
        config.run_compose,
        required,
        timeout=timeout,
        on_change=lambda states: log(
            "waiting for stable service health: "
            + ", ".join(
                f"{name}={value}"
                for name, value in states.items()
                if value != "running healthy"
            )
        ),
    )


def reconcile(*, blocking: bool = False) -> None:
    validate_license()
    build(("control",))
    config.run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "tracecat-seed",
    )
    _wait_exit("tracecat-seed", 600)
    config.run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "gym-reconciler",
    )
    if blocking:
        wait()


def down() -> None:
    config.run_compose(
        "--profile", "bootstrap", "--profile", "evaluation", "down", "--remove-orphans"
    )
    log("Gym 001 stopped; all volumes and credentials were retained.")


def logs(service: str | None) -> None:
    args = ["--profile", "bootstrap", "logs", "--follow", "--tail", "200"]
    if service:
        args.append(service)
    config.run_compose(*args)


def reset(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError(
            "reset destroys Gym 001 state; rerun only after preserving artifacts as `just reset CONFIRM=artifacts-captured`"
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
        "Removed only tracecat-gym-001 containers and volumes. Legacy rollback volumes were retained."
    )


def clean_restart(confirm: str | None) -> None:
    reset(confirm)
    up(allow_fresh_with_legacy=True)


def reset_evals(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise GymError(
            "reset-evals deletes the managed case and its sessions; rerun only after preserving artifacts as `just reset-evals CONFIRM=artifacts-captured`"
        )
    validate_license()
    build(("control",))
    config.run_compose(
        "--profile",
        "bootstrap",
        "run",
        "--rm",
        "--no-deps",
        "gym-reconciler",
        "internal-reset-evals",
    )


def volume_digest(path: Path) -> str:
    return lifecycle.volume_digest(path)


def _volume_digest_in_container(image: str, volume: str) -> str:
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--volume",
            f"{volume}:/volume:ro",
            image,
            "volume-digest",
            "/volume",
        ],
        capture=True,
    )
    return result.stdout.strip().splitlines()[-1]


def migrate() -> None:
    init_env()
    doctor(allow_legacy_ports=True)
    check_upstreams()
    build()
    missing = [
        suffix
        for suffix in config.VOLUME_SUFFIXES
        if not docker_volume_exists(config.volume_name(config.LEGACY_PROJECT, suffix))
    ]
    if missing:
        raise GymError(f"legacy volumes are missing: {missing}")
    if any(
        docker_volume_exists(config.volume_name(config.PROJECT, suffix))
        for suffix in config.VOLUME_SUFFIXES
    ):
        raise GymError(
            "one or more Gym 001 destination volumes already exist; migration refuses to overwrite them"
        )
    log("Stopping the legacy project without removing its volumes...")
    config.run_compose(
        "--profile",
        "bootstrap",
        "--profile",
        "evaluation",
        "down",
        "--remove-orphans",
        project=config.LEGACY_PROJECT,
        check=False,
    )
    image = config.local_image("control")
    manifests: dict[str, dict[str, str]] = {}
    for suffix in config.VOLUME_SUFFIXES:
        source = config.volume_name(config.LEGACY_PROJECT, suffix)
        destination = config.volume_name(config.PROJECT, suffix)
        run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                "org.tracecat.gym.id=001",
                "--label",
                f"com.docker.compose.project={config.PROJECT}",
                "--label",
                f"com.docker.compose.volume={suffix}",
                destination,
            ],
            capture=True,
        )
        log(f"Copying {source} → {destination}...")
        run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0",
                "--entrypoint",
                "/bin/sh",
                "--volume",
                f"{source}:/source:ro",
                "--volume",
                f"{destination}:/dest",
                image,
                "-c",
                "cp -a /source/. /dest/",
            ]
        )
        source_hash = _volume_digest_in_container(image, source)
        destination_hash = _volume_digest_in_container(image, destination)
        if source_hash != destination_hash:
            raise GymError(
                f"volume verification failed for {suffix}: {source_hash} != {destination_hash}"
            )
        manifests[suffix] = {
            "source": source,
            "destination": destination,
            "normalized_sha256": source_hash,
        }
    state_dir = config.ROOT / ".state"
    state_dir.mkdir(exist_ok=True)
    state = {
        "schema_version": 1,
        "migrated_at": datetime.now(UTC).isoformat(),
        "source_project": config.LEGACY_PROJECT,
        "destination_project": config.PROJECT,
        "volumes": manifests,
    }
    (state_dir / "volume-migration.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n"
    )
    _start_stack()
    wait()
    log(
        "Migration accepted: copied state is ready and all legacy volumes remain untouched."
    )


def evaluate(runs: int) -> int:
    build(("control",))
    wait()
    lifecycle.ensure_host_directory(config.ROOT / "eval-results")
    result = config.run_compose(
        "--profile",
        "evaluation",
        "run",
        "--rm",
        "--no-deps",
        "eval-runner",
        "internal-eval",
        "--runs",
        str(runs),
        check=False,
    )
    return result.returncode


def rotate_license(path: Path) -> None:
    metadata = validate_license(expected=False, path=path)
    destination = config.ROOT / "assets/Splunk.License"
    temporary = destination.with_name(f".Splunk.License.{os.getpid()}.tmp")
    shutil.copyfile(path, temporary)
    temporary.replace(destination)
    lock_path = config.LOCK_PATH
    lock = config.load_lock()
    lock["artifacts"]["splunk_license"] = {
        "classification": "user-supplied",
        **metadata,
    }
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")
    build(("splunk",), force=True)
    config.run_compose("up", "--detach", "--force-recreate", "splunk")
    reconcile(blocking=True)
    log(f"Rotated Splunk license; valid through {metadata['expiration_utc']}.")
