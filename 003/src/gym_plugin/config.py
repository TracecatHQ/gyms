"""Gym 003 identity, paths, and deterministic image metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from gymctl import compose
from gymctl.definition import GymDefinition


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2])).resolve()
REPO_ROOT = ROOT.parent
DEFINITION = GymDefinition(
    gym_id="003",
    root=ROOT,
    compose_project="tracecat-gym-003",
    volume_suffixes=(
        "core-db", "temporal-db", "minio-data", "redis-data", "sandbox-cache",
        "gym-jobs", "waf-data", "waf-storage", "waf-logs", "n8n-data",
    ),
    host_port=38080,
    prefer_gym_upstream_images=True,
)
PROJECT = DEFINITION.compose_project


def load_lock() -> dict:
    return json.loads((ROOT / "gym.lock.json").read_text())


def load_platform_lock() -> dict:
    return DEFINITION.load_platform_lock()


def parse_env(path: Path | None = None) -> dict[str, str]:
    return compose.parse_env(DEFINITION, path)


def upstream_image(name: str) -> str:
    return compose.upstream_image(DEFINITION, name)


def _files() -> list[Path]:
    selected: list[Path] = []
    for base in (ROOT / "src", ROOT / "benchmark", ROOT / "images", ROOT / "assets"):
        if base.exists():
            selected.extend(path for path in base.rglob("*") if path.is_file())
    selected.extend(path for path in (REPO_ROOT / "src/gymctl").rglob("*.py"))
    selected.extend(
        (ROOT / name)
        for name in ("compose.override.yml", "Justfile", "PROVENANCE.md")
    )
    return [p for p in selected if "__pycache__" not in p.parts and p.suffix != ".pyc"]


def image_input_hash(component: str = "control") -> str:
    if component != "control":
        raise ValueError(f"unknown image component: {component}")
    digest = hashlib.sha256()
    for path in sorted(_files()):
        digest.update(path.relative_to(REPO_ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    lock = load_lock()
    local = lock.get("images", {}).get("local", {}).get("control", {})
    normalized = {
        **lock,
        "images": {
            **lock.get("images", {}),
            "local": {"control": {k: v for k, v in local.items() if k != "input_sha256"}},
        },
    }
    digest.update(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode())
    return digest.hexdigest()


def local_image(component: str = "control") -> str:
    if component != "control":
        raise ValueError(f"unknown image component: {component}")
    return f"{load_lock()['images']['local']['control']['repository']}:{image_input_hash()[:16]}"


def compose_environment() -> dict[str, str]:
    return compose.compose_environment(DEFINITION, {"GYM_CONTROL_IMAGE": local_image()})


def compose_args(*args: str) -> list[str]:
    return compose.compose_args(DEFINITION, *args)


def run_compose(*args: str, check: bool = True, capture: bool = False):
    return compose.run_compose(
        DEFINITION, {"GYM_CONTROL_IMAGE": local_image()}, *args,
        check=check, capture=capture,
    )
