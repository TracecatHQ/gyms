"""Gym 001 definition and deterministic image identities."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from gymctl import compose
from gymctl.definition import GymDefinition


def root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    if configured:
        return Path(configured).resolve()
    return Path(__file__).resolve().parents[2]


ROOT = root()
REPO_ROOT = ROOT.parent
DEFINITION = GymDefinition(
    gym_id="001",
    root=ROOT,
    compose_project="tracecat-gym-001",
    legacy_compose_project="the-bigger-interview",
    volume_suffixes=(
        "core-db",
        "temporal-db",
        "minio-data",
        "redis-data",
        "sandbox-cache",
        "splunk-etc",
        "splunk-var",
    ),
    host_port=18080,
    prefer_gym_upstream_images=True,
)
PROJECT = DEFINITION.compose_project
LEGACY_PROJECT = DEFINITION.legacy_compose_project or ""
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


def _hash_file(hasher: "hashlib._Hash", path: Path, label: str) -> None:
    hasher.update(label.encode())
    hasher.update(b"\0")
    hasher.update(path.read_bytes())
    hasher.update(b"\0")


def _hash_tree(hasher: "hashlib._Hash", path: Path, label: str) -> None:
    for item in sorted(
        candidate for candidate in path.rglob("*") if candidate.is_file()
    ):
        if "__pycache__" in item.parts or item.suffix == ".pyc":
            continue
        _hash_file(hasher, item, f"{label}/{item.relative_to(path).as_posix()}")


def image_input_hash(component: str) -> str:
    lock = load_lock()
    hasher = hashlib.sha256()
    if component == "splunk":
        _hash_file(hasher, ROOT / "images/splunk/Dockerfile", "Dockerfile")
        _hash_tree(hasher, ROOT / "images/splunk", "images/splunk")
        _hash_tree(hasher, ROOT / "upstream/dataset/conf", "dataset/conf")
        _hash_tree(hasher, ROOT / "upstream/dataset/logs", "dataset/logs")
        _hash_file(hasher, ROOT / "assets/splunk-mcp-server_200.tgz", "mcp")
        selected = {
            "base": lock["images"]["upstream"]["splunk"],
            "dataset": lock["sources"]["dataset"],
            "artifacts": lock["artifacts"],
            "expectations": lock["expectations"],
        }
    elif component == "control":
        _hash_file(hasher, ROOT / "images/control/Dockerfile", "Dockerfile")
        _hash_tree(hasher, ROOT / "src", "src")
        _hash_tree(hasher, REPO_ROOT / "src/gymctl", "shared/gymctl")
        _hash_tree(hasher, ROOT / "benchmark", "benchmark")
        selected = {
            "platform": load_platform_lock(),
            "lock": {
                **lock,
                "images": {
                    **lock["images"],
                    "local": {
                        key: {
                            field: value
                            for field, value in item.items()
                            if field != "input_sha256"
                        }
                        for key, item in lock["images"]["local"].items()
                    },
                },
            },
        }
    else:
        raise ValueError(f"unknown image component: {component}")
    hasher.update(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode())
    return hasher.hexdigest()


def local_image(component: str) -> str:
    repository = load_lock()["images"]["local"][component]["repository"]
    return f"{repository}:{image_input_hash(component)[:16]}"


def compose_environment() -> dict[str, str]:
    return compose.compose_environment(
        DEFINITION,
        {
            "GYM_SPLUNK_IMAGE": local_image("splunk"),
            "GYM_CONTROL_IMAGE": local_image("control"),
        },
    )


def compose_args(*args: str, project: str = PROJECT) -> list[str]:
    return compose.compose_args(DEFINITION, *args, project=project)


def run_compose(
    *args: str, project: str = PROJECT, check: bool = True, capture: bool = False
):
    return compose.run_compose(
        DEFINITION,
        {
            "GYM_SPLUNK_IMAGE": local_image("splunk"),
            "GYM_CONTROL_IMAGE": local_image("control"),
        },
        *args,
        project=project,
        check=check,
        capture=capture,
    )


def volume_name(project: str, suffix: str) -> str:
    return compose.volume_name(project, suffix)
