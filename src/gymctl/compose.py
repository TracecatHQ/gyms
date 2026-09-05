"""Compose paths, environment, invocation, and host-identity handling."""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

from .definition import GymDefinition


def parse_env(definition: GymDefinition, path: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    source = path or definition.root / ".env"
    if source.is_file():
        for raw in source.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"').strip("'")
    return values


def upstream_image(definition: GymDefinition, name: str) -> str:
    platform = definition.load_platform_lock()["images"]
    gym_images = definition.load_lock().get("images", {}).get("upstream", {})
    item = (
        gym_images.get(name) if definition.prefer_gym_upstream_images else None
    ) or platform[name]
    return f"{item['source_ref']}@{item['digest']}"


def compose_environment(
    definition: GymDefinition, local_images: dict[str, str]
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GYM_ROOT": str(definition.root),
            "COMPOSE_PROJECT_NAME": definition.compose_project,
            "GYM_CADDYFILE_B64": base64.b64encode(
                (definition.repo_root / "upstream/tracecat/Caddyfile").read_bytes()
            ).decode(),
            "GYM_HOST_UID": str(os.getuid()),
            "GYM_HOST_GID": str(os.getgid()),
            **local_images,
            **{
                f"IMAGE_{name.upper()}": upstream_image(definition, name)
                for name in definition.load_platform_lock()["images"]
            },
        }
    )
    return env


def compose_args(
    definition: GymDefinition, *args: str, project: str | None = None
) -> list[str]:
    common_env = definition.repo_root / "config/tracecat.env.example"
    configured_env = definition.root / ".env"
    gym_env = (
        configured_env if configured_env.is_file() else definition.root / ".env.example"
    )
    return [
        "docker",
        "compose",
        "--project-name",
        project or definition.compose_project,
        "--project-directory",
        str(definition.root),
        "--env-file",
        str(common_env),
        "--env-file",
        str(gym_env),
        "-f",
        str(definition.repo_root / "upstream/tracecat/docker-compose.yml"),
        "-f",
        str(definition.repo_root / "compose/tracecat.override.yml"),
        "-f",
        str(definition.root / "compose.override.yml"),
        *args,
    ]


def run_compose(
    definition: GymDefinition,
    local_images: dict[str, str],
    *args: str,
    project: str | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        compose_args(definition, *args, project=project),
        cwd=definition.root,
        env=compose_environment(definition, local_images),
        check=check,
        text=True,
        capture_output=capture,
    )


def volume_name(project: str, suffix: str) -> str:
    return f"{project}_{suffix}"
