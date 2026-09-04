"""Host-side lifecycle for Gym 001. Standard-library only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import config
from .license import LicenseError, load_metadata, validate_current


class GymError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[gym-001] {message}", flush=True)


def run(command: list[str], *, check: bool = True, capture: bool = False, env: dict[str, str] | None = None):
    return subprocess.run(
        command,
        cwd=config.ROOT,
        check=check,
        text=True,
        capture_output=capture,
        env=env,
    )


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def docker_volume_exists(name: str) -> bool:
    return subprocess.run(
        ["docker", "volume", "inspect", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def validate_license(*, expected: bool = True, path: Path | None = None) -> dict[str, object]:
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
    source = config.ROOT / ".env.example"
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
    output: list[str] = []
    postgres_password = replacements["TRACECAT__POSTGRES_PASSWORD"]
    for line in source.read_text().splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in replacements:
            line = f"{key}={replacements[key]}"
        elif key == "TRACECAT__DB_URI":
            line = f"TRACECAT__DB_URI=postgresql+psycopg://postgres:{postgres_password}@postgres_db:5432/postgres"
        output.append(line)
    temporary = config.ROOT / f".env.tmp.{os.getpid()}"
    old_umask = os.umask(0o077)
    try:
        temporary.write_text("\n".join(output) + "\n")
        temporary.replace(target)
    finally:
        os.umask(old_umask)
    target.chmod(0o600)
    log("Created .env with random credentials and mode 0600.")
    validate_license()


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(item) for item in re.findall(r"\d+", value)[:3])


def doctor(*, allow_legacy_ports: bool = False) -> None:
    for name in ("docker", "git", "just", "curl", "openssl", "uvx"):
        if not command_exists(name):
            raise GymError(f"required command is missing: {name}")
    run(["docker", "info"], capture=True)
    version = run(["docker", "compose", "version", "--short"], capture=True).stdout.strip().lstrip("v")
    if _version_tuple(version) < (2, 24, 4):
        raise GymError(f"Docker Compose {version} is too old; 2.24.4+ is required")
    available = shutil.disk_usage(config.ROOT).free
    if available < 30 * 1024**3:
        raise GymError(f"30 GiB free disk is required; {available / 1024**3:.1f} GiB is available. Nothing was pruned.")
    if run(["git", "-C", str(config.ROOT.parent), "submodule", "status", "--", "001/upstream/dataset"], capture=True).stdout.startswith("-"):
        raise GymError("dataset submodule is missing; run git submodule update --init --recursive")
    lock = config.load_lock()
    head = run(["git", "-C", str(config.ROOT / "upstream/dataset"), "rev-parse", "HEAD"], capture=True).stdout.strip()
    if head != lock["sources"]["dataset"]["commit"]:
        raise GymError(f"dataset submodule is at {head}, expected {lock['sources']['dataset']['commit']}")
    env = config.parse_env()
    if env.get("SPLUNK_ACCEPT_TERMS") != "yes":
        raise GymError("Splunk terms acceptance is not recorded in .env")
    for port in (18080, 18000):
        rows = run(["docker", "ps", "--filter", f"publish={port}", "--format", "{{.ID}}"], capture=True).stdout.split()
        for container in rows:
            owner = run(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}', container], capture=True).stdout.strip()
            allowed = {config.PROJECT}
            if allow_legacy_ports:
                allowed.add(config.LEGACY_PROJECT)
            if owner not in allowed:
                raise GymError(f"port {port} belongs to Docker project {owner or 'unknown'} ({container})")
        if not rows:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    raise GymError(f"host port {port} is already occupied outside this gym")
    validate_license()
    if os.uname().machine == "arm64":
        log("Splunk is amd64-only; Docker emulation will be used on Apple Silicon.")
        run(["docker", "run", "--rm", "--platform", "linux/amd64", "--entrypoint", "/bin/true", config.upstream_image("splunk")])
        log("Splunk 10.4's AVX installer probe is bypassed because translated containers cannot expose AVX; legacy migration volumes remain rollback-safe.")
    log(f"Doctor passed: Compose {version}; {available / 1024**3:.1f} GiB free.")


def _remote_digest(reference: str) -> str:
    result = run(
        ["docker", "buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest}}"],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise GymError(f"could not inspect OCI reference {reference}: {result.stderr.strip()[-300:]}")
    payload = json.loads(result.stdout)
    digest = payload.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise GymError(f"registry returned no image-index digest for {reference}")
    return digest


def check_upstreams() -> None:
    lock = config.load_lock()
    allow_stale = os.environ.get("ALLOW_STALE_UPSTREAM") == "1"
    try:
        request = urllib.request.Request(
            "https://api.github.com/repos/TracecatHQ/tracecat/releases?per_page=50",
            headers={"User-Agent": "tracecat-gyms/001"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            releases = json.load(response)
        latest = max((item for item in releases if not item.get("draft")), key=lambda item: item["published_at"])
        expected_tag = lock["sources"]["tracecat"]["tag"]
        if latest["tag_name"] != expected_tag:
            raise GymError(f"Tracecat is pinned to {expected_tag}, but latest published stable/RC is {latest['tag_name']}; run just update-upstreams")
        for name, item in lock["images"]["upstream"].items():
            observed = _remote_digest(item["source_ref"])
            if observed != item["digest"]:
                raise GymError(f"upstream image moved for {name}: expected {item['digest']}, got {observed}")
    except Exception as exc:
        if not allow_stale:
            if isinstance(exc, GymError):
                raise
            raise GymError(f"upstream check failed closed: {exc}") from exc
        log(f"WARNING: upstream verification bypassed by ALLOW_STALE_UPSTREAM=1: {exc}")
    else:
        log(f"Upstreams are current and immutable at {lock['sources']['tracecat']['tag']}.")


def _image_label(image: str, key: str) -> str | None:
    result = run(["docker", "image", "inspect", image, "--format", f'{{{{index .Config.Labels "{key}"}}}}'], check=False, capture=True)
    return result.stdout.strip() if result.returncode == 0 else None


def build(components: tuple[str, ...] = ("splunk", "control"), *, force: bool = False) -> None:
    lock = config.load_lock()
    revision = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    for component in components:
        digest = config.image_input_hash(component)
        image = config.local_image(component)
        if not force and _image_label(image, "org.tracecat.gym.input-sha") == digest:
            log(f"{component} image is current: {image}")
            continue
        command = ["docker", "build", "--file", str(config.ROOT / f"images/{component}/Dockerfile"), "--tag", image]
        if component == "splunk":
            command += ["--platform", "linux/amd64", "--build-arg", f"SPLUNK_IMAGE={config.upstream_image('splunk')}", "--build-arg", f"DATASET_COMMIT={lock['sources']['dataset']['commit']}", "--build-arg", "SPLUNK_VERSION=10.4.1", "--build-arg", f"MCP_VERSION={lock['artifacts']['splunk_mcp']['version']}"]
        else:
            command += ["--build-arg", f"TRACECAT_IMAGE={config.upstream_image('tracecat')}", "--build-arg", f"TRACECAT_VERSION={lock['sources']['tracecat']['tag']}"]
        command += ["--build-arg", f"GYM_COMPONENT_VERSION={lock['gym']['component_version']}", "--build-arg", f"GYM_INPUT_SHA={digest}", "--build-arg", f"GYM_REVISION={revision}", str(config.ROOT)]
        log(f"Building {component} image {image}...")
        run(command)
        observed = _image_label(image, "org.tracecat.gym.input-sha")
        if observed != digest:
            raise GymError(f"built {component} image label mismatch: expected {digest}, got {observed}")


def _container_id(service: str, profile: str | None = None) -> str:
    args = (["--profile", profile] if profile else []) + ["ps", "--all", "--quiet", service]
    rows = config.run_compose(*args, capture=True).stdout.strip().splitlines()
    return rows[0] if rows else ""


def _wait_exit(service: str, timeout: int, profile: str = "bootstrap") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container = _container_id(service, profile)
        if container:
            state = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", container], capture=True).stdout.strip()
            if state.startswith("exited "):
                code = int(state.split()[1])
                if code:
                    config.run_compose("--profile", profile, "logs", "--no-color", service, check=False)
                    raise GymError(f"{service} exited with status {code}")
                return
        time.sleep(2)
    raise GymError(f"timed out waiting for {service}")


def _start_stack() -> None:
    config.run_compose("up", "--detach")
    config.run_compose("--profile", "bootstrap", "up", "--detach", "--no-deps", "--force-recreate", "tracecat-seed")
    _wait_exit("tracecat-seed", 600)
    config.run_compose("--profile", "bootstrap", "up", "--detach", "--no-deps", "--force-recreate", "gym-reconciler")
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:18080/api/health", timeout=5) as response:
                if response.status == 200:
                    log("Tracecat is ready; Splunk reconciliation continues asynchronously.")
                    info()
                    return
        except Exception:
            time.sleep(3)
    raise GymError("Tracecat did not become ready within 10 minutes")


def up(*, allow_fresh_with_legacy: bool = False) -> None:
    init_env()
    doctor(allow_legacy_ports=False)
    check_upstreams()
    new = [docker_volume_exists(config.volume_name(config.PROJECT, suffix)) for suffix in config.VOLUME_SUFFIXES]
    legacy = [docker_volume_exists(config.volume_name(config.LEGACY_PROJECT, suffix)) for suffix in config.VOLUME_SUFFIXES]
    if any(legacy) and not any(new) and not allow_fresh_with_legacy:
        raise GymError("legacy The Bigger Interview volumes exist while Gym 001 volumes do not; run `just migrate` to preserve state")
    build()
    _start_stack()


def info() -> None:
    env = config.parse_env()
    if not env:
        raise GymError(".env is missing; run SPLUNK_ACCEPT_TERMS=yes just up")
    print("Tracecat UI: http://127.0.0.1:18080")
    print(f"  Tenant: {env['TRACEcat_TENANT_EMAIL']} / {env['TRACEcat_TENANT_PASSWORD']}")
    print(f"  Superadmin: {env['TRACEcat_SUPERADMIN_EMAIL']} / {env['TRACEcat_SUPERADMIN_PASSWORD']}")
    print("Splunk UI: http://127.0.0.1:18000")
    print(f"  Admin: {env['SPLUNK_ADMIN_USER']} / {env['SPLUNK_ADMIN_PASSWORD']}")


def status() -> None:
    validate_license()
    config.run_compose("--profile", "bootstrap", "ps", "--all", check=False)
    if _container_id("api"):
        config.run_compose("--profile", "bootstrap", "run", "--rm", "--no-deps", "gym-reconciler", "internal-reconcile", "status")


def wait() -> None:
    container = _container_id("gym-reconciler", "bootstrap")
    if not container:
        raise GymError("gym reconciler is not running; run just up or just reconcile")
    last = 0.0
    while True:
        state = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", container], capture=True).stdout.strip()
        if state.startswith("exited "):
            config.run_compose("--profile", "bootstrap", "logs", "--no-color", "gym-reconciler", check=False)
            if state != "exited 0":
                raise GymError(f"gym reconciliation failed: {state}")
            _wait_runtime_health(600)
            log("Full Gym 001 readiness checks passed.")
            return
        if time.monotonic() - last > 30:
            run(["docker", "logs", "--tail", "1", container], check=False)
            last = time.monotonic()
        time.sleep(5)


def _wait_runtime_health(timeout: int) -> None:
    required = ("api", "litellm", "postgres_db", "temporal", "minio", "redis", "splunk", "splunk-mcp-compat")
    deadline = time.monotonic() + timeout
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        states: dict[str, str] = {}
        for service in required:
            container = _container_id(service)
            if not container:
                states[service] = "missing"
                continue
            raw = run(["docker", "inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container], capture=True).stdout.strip()
            states[service] = raw
        if all(value == "running healthy" for value in states.values()):
            return
        if states != last:
            log("waiting for stable service health: " + ", ".join(f"{name}={value}" for name, value in states.items() if value != "running healthy"))
            last = states
        time.sleep(5)
    raise GymError("services did not reach stable health: " + json.dumps(last, sort_keys=True))


def reconcile(*, blocking: bool = False) -> None:
    validate_license()
    build(("control",))
    config.run_compose("--profile", "bootstrap", "up", "--detach", "--no-deps", "--force-recreate", "tracecat-seed")
    _wait_exit("tracecat-seed", 600)
    config.run_compose("--profile", "bootstrap", "up", "--detach", "--no-deps", "--force-recreate", "gym-reconciler")
    if blocking:
        wait()


def down() -> None:
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "down", "--remove-orphans")
    log("Gym 001 stopped; all volumes and credentials were retained.")


def logs(service: str | None) -> None:
    args = ["--profile", "bootstrap", "logs", "--follow", "--tail", "200"]
    if service:
        args.append(service)
    config.run_compose(*args)


def reset(confirm: str | None) -> None:
    if confirm != "001":
        raise GymError("reset destroys Gym 001 state; rerun as `just reset CONFIRM=001`")
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "down", "--volumes", "--remove-orphans")
    log("Removed only tracecat-gym-001 containers and volumes. Legacy rollback volumes were retained.")


def clean_restart(confirm: str | None) -> None:
    reset(confirm)
    up(allow_fresh_with_legacy=True)


def volume_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*"), key=lambda value: value.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix()
        details = item.lstat()
        if item.is_symlink():
            kind, payload = "L", os.readlink(item).encode()
        elif item.is_dir():
            kind, payload = "D", b""
        elif item.is_file():
            kind, payload = "F", item.read_bytes()
        else:
            kind, payload = "O", b""
        header = f"{relative}\0{kind}\0{stat.S_IMODE(details.st_mode):o}\0{details.st_uid}\0{details.st_gid}\0".encode()
        digest.update(header)
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _volume_digest_in_container(image: str, volume: str) -> str:
    result = run(["docker", "run", "--rm", "--user", "0", "--volume", f"{volume}:/volume:ro", image, "volume-digest", "/volume"], capture=True)
    return result.stdout.strip().splitlines()[-1]


def migrate() -> None:
    init_env()
    doctor(allow_legacy_ports=True)
    check_upstreams()
    build()
    missing = [suffix for suffix in config.VOLUME_SUFFIXES if not docker_volume_exists(config.volume_name(config.LEGACY_PROJECT, suffix))]
    if missing:
        raise GymError(f"legacy volumes are missing: {missing}")
    if any(docker_volume_exists(config.volume_name(config.PROJECT, suffix)) for suffix in config.VOLUME_SUFFIXES):
        raise GymError("one or more Gym 001 destination volumes already exist; migration refuses to overwrite them")
    log("Stopping the legacy project without removing its volumes...")
    config.run_compose("--profile", "bootstrap", "--profile", "evaluation", "down", "--remove-orphans", project=config.LEGACY_PROJECT, check=False)
    image = config.local_image("control")
    manifests: dict[str, dict[str, str]] = {}
    for suffix in config.VOLUME_SUFFIXES:
        source = config.volume_name(config.LEGACY_PROJECT, suffix)
        destination = config.volume_name(config.PROJECT, suffix)
        run([
            "docker", "volume", "create",
            "--label", "org.tracecat.gym.id=001",
            "--label", f"com.docker.compose.project={config.PROJECT}",
            "--label", f"com.docker.compose.volume={suffix}",
            destination,
        ], capture=True)
        log(f"Copying {source} → {destination}...")
        run(["docker", "run", "--rm", "--user", "0", "--entrypoint", "/bin/sh", "--volume", f"{source}:/source:ro", "--volume", f"{destination}:/dest", image, "-c", "cp -a /source/. /dest/"])
        source_hash = _volume_digest_in_container(image, source)
        destination_hash = _volume_digest_in_container(image, destination)
        if source_hash != destination_hash:
            raise GymError(f"volume verification failed for {suffix}: {source_hash} != {destination_hash}")
        manifests[suffix] = {"source": source, "destination": destination, "normalized_sha256": source_hash}
    state_dir = config.ROOT / ".state"
    state_dir.mkdir(exist_ok=True)
    state = {
        "schema_version": 1,
        "migrated_at": datetime.now(UTC).isoformat(),
        "source_project": config.LEGACY_PROJECT,
        "destination_project": config.PROJECT,
        "volumes": manifests,
    }
    (state_dir / "volume-migration.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    _start_stack()
    wait()
    status()
    log("Migration accepted: copied state is ready and all legacy volumes remain untouched.")


def evaluate(runs: int) -> None:
    wait()
    config.run_compose("--profile", "evaluation", "run", "--rm", "--no-deps", "eval-runner", "internal-eval", "--runs", str(runs))


def rotate_license(path: Path) -> None:
    metadata = validate_license(expected=False, path=path)
    destination = config.ROOT / "assets/Splunk.License"
    temporary = destination.with_name(f".Splunk.License.{os.getpid()}.tmp")
    shutil.copyfile(path, temporary)
    temporary.replace(destination)
    lock_path = config.LOCK_PATH
    lock = config.load_lock()
    lock["artifacts"]["splunk_license"] = {"classification": "user-supplied", **metadata}
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")
    build(("splunk",), force=True)
    config.run_compose("up", "--detach", "--force-recreate", "splunk")
    reconcile(blocking=True)
    log(f"Rotated Splunk license; valid through {metadata['expiration_utc']}.")
