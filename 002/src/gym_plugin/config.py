"""Paths, immutable image references, and Compose invocation."""

from __future__ import annotations
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

PROJECT = "tracecat-gym-002"
VOLUME_SUFFIXES = (
    "core-db",
    "temporal-db",
    "minio-data",
    "redis-data",
    "sandbox-cache",
)


def root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    return (
        Path(configured).resolve()
        if configured
        else Path(__file__).resolve().parents[2]
    )


ROOT = root()
REPO_ROOT = ROOT.parent
LOCK_PATH = ROOT / "gym.lock.json"
PLATFORM_LOCK_PATH = REPO_ROOT / "platform.lock.json"


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text())


def load_platform_lock() -> dict:
    return json.loads(PLATFORM_LOCK_PATH.read_text())


def parse_env(path: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    source = path or ROOT / ".env"
    if source.is_file():
        for raw in source.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"').strip("'")
    return values


def upstream_image(name: str) -> str:
    item = load_platform_lock()["images"][name]
    return f"{item['source_ref']}@{item['digest']}"


def image_input_hash() -> str:
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


def local_image() -> str:
    return f"{load_lock()['images']['local']['control']['repository']}:{image_input_hash()[:16]}"


def compose_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GYM_ROOT": str(ROOT),
            "COMPOSE_PROJECT_NAME": PROJECT,
            "GYM_CONTROL_IMAGE": local_image(),
            "GYM_CADDYFILE_B64": base64.b64encode(
                (REPO_ROOT / "upstream/tracecat/Caddyfile").read_bytes()
            ).decode(),
            **{
                f"IMAGE_{name.upper()}": upstream_image(name)
                for name in load_platform_lock()["images"]
            },
        }
    )
    return env


def compose_args(*args: str) -> list[str]:
    common_env = REPO_ROOT / "config/tracecat.env.example"
    gym_env = ROOT / (".env" if (ROOT / ".env").is_file() else ".env.example")
    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--project-directory",
        str(ROOT),
        "--env-file",
        str(common_env),
        "--env-file",
        str(gym_env),
        "-f",
        str(REPO_ROOT / "upstream/tracecat/docker-compose.yml"),
        "-f",
        str(REPO_ROOT / "compose/tracecat.override.yml"),
        "-f",
        str(ROOT / "compose.override.yml"),
        *args,
    ]


def run_compose(*args: str, check: bool = True, capture: bool = False):
    return subprocess.run(
        compose_args(*args),
        cwd=ROOT,
        env=compose_environment(),
        check=check,
        text=True,
        capture_output=capture,
    )
