"""Gym 002 definition and deterministic control-image identity."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from gymctl import compose
from gymctl.definition import GymDefinition


def root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    return (
        Path(configured).resolve()
        if configured
        else Path(__file__).resolve().parents[2]
    )


ROOT = root()
REPO_ROOT = ROOT.parent
DEFINITION = GymDefinition(
    gym_id="002",
    root=ROOT,
    compose_project="tracecat-gym-002",
    volume_suffixes=(
        "core-db",
        "temporal-db",
        "minio-data",
        "redis-data",
        "sandbox-cache",
    ),
    host_port=28080,
)
PROJECT = DEFINITION.compose_project
VOLUME_SUFFIXES = DEFINITION.volume_suffixes
LOCK_PATH = ROOT / "gym.lock.json"
PLATFORM_LOCK_PATH = REPO_ROOT / "platform.lock.json"


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text())


def load_platform_lock() -> dict:
    return json.loads(PLATFORM_LOCK_PATH.read_text())


def parse_env(path: Path | None = None) -> dict[str, str]:
    return compose.parse_env(DEFINITION, path)


def upstream_image(name: str) -> str:
    return compose.upstream_image(DEFINITION, name)


def image_input_hash(component: str = "control") -> str:
    if component != "control":
        raise ValueError(f"unknown image component: {component}")
    hasher = hashlib.sha256()
    paths = list((ROOT / "src").rglob("*.py")) + list((ROOT / "benchmark").rglob("*"))
    paths = [
        path
        for path in paths
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    ]
    paths += list((REPO_ROOT / "src/gymctl").rglob("*.py"))
    paths += [ROOT / "images/control/Dockerfile", REPO_ROOT / "platform.lock.json"]
    for path in sorted(paths):
        label = path.relative_to(REPO_ROOT).as_posix()
        hasher.update(label.encode() + b"\0" + path.read_bytes())
    lock = load_lock()
    local = lock["images"]["local"]["control"]
    normalized = {
        **lock,
        "images": {
            **lock["images"],
            "local": {
                "control": {
                    key: value for key, value in local.items() if key != "input_sha256"
                }
            },
        },
    }
    hasher.update(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    )
    return hasher.hexdigest()


def local_image(component: str = "control") -> str:
    if component != "control":
        raise ValueError(f"unknown image component: {component}")
    return f"{load_lock()['images']['local']['control']['repository']}:{image_input_hash()[:16]}"


def compose_environment() -> dict[str, str]:
    return compose.compose_environment(
        DEFINITION, {"GYM_CONTROL_IMAGE": local_image("control")}
    )


def compose_args(*args: str) -> list[str]:
    return compose.compose_args(DEFINITION, *args)


def run_compose(*args: str, check: bool = True, capture: bool = False):
    return compose.run_compose(
        DEFINITION,
        {"GYM_CONTROL_IMAGE": local_image("control")},
        *args,
        check=check,
        capture=capture,
    )
