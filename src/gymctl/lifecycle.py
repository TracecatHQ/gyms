"""Reusable host lifecycle primitives for numbered gyms."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from .definition import GymDefinition


class LifecycleError(RuntimeError):
    pass


def run(
    root: Path,
    command: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        env=env,
        check=check,
        text=True,
        capture_output=capture,
    )


def write_env(
    definition: GymDefinition,
    replacements: dict[str, str],
) -> Path:
    """Atomically materialize common plus gym env templates with mode 0600."""

    sources = (
        definition.repo_root / "config/tracecat.env.example",
        definition.root / ".env.example",
    )
    output: list[str] = []
    postgres_password = replacements["TRACECAT__POSTGRES_PASSWORD"]
    for line in "\n".join(
        source.read_text().rstrip() for source in sources
    ).splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in replacements:
            line = f"{key}={replacements[key]}"
        elif key == "TRACECAT__DB_URI":
            line = (
                "TRACECAT__DB_URI=postgresql+psycopg://postgres:"
                f"{postgres_password}@postgres_db:5432/postgres"
            )
        output.append(line)
    target = definition.root / ".env"
    temporary = definition.root / f".env.tmp.{os.getpid()}"
    previous_umask = os.umask(0o077)
    try:
        temporary.write_text("\n".join(output) + "\n")
        temporary.replace(target)
    finally:
        os.umask(previous_umask)
    target.chmod(0o600)
    return target


def image_label(root: Path, image: str, key: str) -> str | None:
    result = run(
        root,
        [
            "docker",
            "image",
            "inspect",
            image,
            "--format",
            f'{{{{index .Config.Labels "{key}"}}}}',
        ],
        check=False,
        capture=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def build_image(
    definition: GymDefinition,
    *,
    image: str,
    dockerfile: Path,
    context: Path,
    input_digest: str,
    build_args: dict[str, str],
    build_contexts: dict[str, Path] | None = None,
    force: bool = False,
    label_key: str = "org.tracecat.gym.input-sha",
) -> bool:
    """Build an image iff its content label differs; return whether it built."""

    if not force and image_label(definition.root, image, label_key) == input_digest:
        return False
    command = ["docker", "build", "--file", str(dockerfile), "--tag", image]
    for name, path in sorted((build_contexts or {}).items()):
        command += ["--build-context", f"{name}={path}"]
    for name, value in build_args.items():
        command += ["--build-arg", f"{name}={value}"]
    command.append(str(context))
    run(definition.root, command)
    if image_label(definition.root, image, label_key) != input_digest:
        raise LifecycleError(f"built image label mismatch: {image}")
    return True


def container_id(
    run_compose: Callable[..., subprocess.CompletedProcess[str]],
    service: str,
    *,
    profile: str | None = "bootstrap",
) -> str:
    args: list[str] = []
    if profile:
        args += ["--profile", profile]
    args += ["ps", "--all", "--quiet", service]
    rows = run_compose(*args, capture=True).stdout.strip().splitlines()
    return rows[0] if rows else ""


def wait_exit(
    definition: GymDefinition,
    run_compose: Callable[..., subprocess.CompletedProcess[str]],
    service: str,
    *,
    timeout: int,
    profile: str = "bootstrap",
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container = container_id(run_compose, service, profile=profile)
        if container:
            state = run(
                definition.root,
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
                    run_compose(
                        "--profile",
                        profile,
                        "logs",
                        "--no-color",
                        service,
                        check=False,
                    )
                    raise LifecycleError(f"{service} failed: {state}")
                return
        time.sleep(2)
    raise LifecycleError(f"timed out waiting for {service}")


def run_bootstrap(
    definition: GymDefinition,
    run_compose: Callable[..., subprocess.CompletedProcess[str]],
    service: str,
    *,
    timeout: int,
) -> None:
    run_compose(
        "--profile",
        "bootstrap",
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        service,
    )
    wait_exit(
        definition,
        run_compose,
        service,
        timeout=timeout,
        profile="bootstrap",
    )


def wait_runtime_health(
    definition: GymDefinition,
    run_compose: Callable[..., subprocess.CompletedProcess[str]],
    services: Iterable[str],
    *,
    timeout: int,
    on_change: Callable[[dict[str, str]], None] | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    previous: dict[str, str] = {}
    while time.monotonic() < deadline:
        states: dict[str, str] = {}
        for service in services:
            container = container_id(run_compose, service)
            if not container:
                states[service] = "missing"
                continue
            states[service] = run(
                definition.root,
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    container,
                ],
                capture=True,
            ).stdout.strip()
        if states and all(value == "running healthy" for value in states.values()):
            return
        if states != previous and on_change:
            on_change(states)
        previous = states
        time.sleep(5)
    raise LifecycleError(f"services did not become healthy: {previous}")


def ensure_host_directory(path: Path, *, mode: int = 0o700) -> None:
    """Create a bind source as the invoking user and verify it is usable."""

    path.mkdir(parents=True, mode=mode, exist_ok=True)
    if not path.is_dir() or not os.access(path, os.W_OK | os.X_OK):
        raise LifecycleError(
            f"host directory is not writable by uid {os.getuid()}: {path}"
        )


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
            f"{relative}\0{kind}\0{stat.S_IMODE(details.st_mode):o}\0"
            f"{details.st_uid}\0{details.st_gid}\0".encode()
        )
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()
