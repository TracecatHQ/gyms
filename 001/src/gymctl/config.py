"""Paths, lock data, deterministic image hashes, and Compose invocation."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import base64
from pathlib import Path
from typing import Iterable


PROJECT = "tracecat-gym-001"
LEGACY_PROJECT = "the-bigger-interview"
VOLUME_SUFFIXES = (
    "core-db",
    "temporal-db",
    "minio-data",
    "redis-data",
    "sandbox-cache",
    "splunk-etc",
    "splunk-var",
)


def root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    if configured:
        return Path(configured).resolve()
    return Path(__file__).resolve().parents[2]


ROOT = root()
LOCK_PATH = ROOT / "gym.lock.json"


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text())


def parse_env(path: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    source = path or ROOT / ".env"
    if not source.is_file():
        return values
    for raw in source.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def upstream_image(name: str) -> str:
    item = load_lock()["images"]["upstream"][name]
    return f"{item['source_ref']}@{item['digest']}"


def _hash_file(hasher: "hashlib._Hash", path: Path, label: str) -> None:
    hasher.update(label.encode())
    hasher.update(b"\0")
    hasher.update(path.read_bytes())
    hasher.update(b"\0")


def _hash_tree(hasher: "hashlib._Hash", path: Path, label: str) -> None:
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
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
        _hash_tree(hasher, ROOT / "benchmark", "benchmark")
        selected = {
            "lock": {
                **lock,
                "images": {
                    **lock["images"],
                    "local": {
                        key: {field: value for field, value in item.items() if field != "input_sha256"}
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
    env = os.environ.copy()
    env.update(
        {
            "GYM_ROOT": str(ROOT),
            "GYM_SPLUNK_IMAGE": local_image("splunk"),
            "GYM_CONTROL_IMAGE": local_image("control"),
            "GYM_CADDYFILE_B64": base64.b64encode((ROOT / "upstream/tracecat/Caddyfile").read_bytes()).decode(),
            "IMAGE_CADDY": upstream_image("caddy"),
            "IMAGE_TRACECAT": upstream_image("tracecat"),
            "IMAGE_TRACECAT_UI": upstream_image("tracecat_ui"),
            "IMAGE_POSTGRES": upstream_image("postgres"),
            "IMAGE_TEMPORAL_POSTGRES": upstream_image("temporal_postgres"),
            "IMAGE_TEMPORAL": upstream_image("temporal"),
            "IMAGE_TEMPORAL_UI": upstream_image("temporal_ui"),
            "IMAGE_MINIO": upstream_image("minio"),
            "IMAGE_REDIS": upstream_image("redis"),
        }
    )
    return env


def compose_args(*args: str, project: str = PROJECT) -> list[str]:
    env_file = ROOT / ".env"
    if not env_file.is_file():
        env_file = ROOT / ".env.example"
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(ROOT),
        "--env-file",
        str(env_file),
        "-f",
        str(ROOT / "upstream/tracecat/docker-compose.yml"),
        "-f",
        str(ROOT / "compose.override.yml"),
        *args,
    ]


def run_compose(*args: str, project: str = PROJECT, check: bool = True, capture: bool = False):
    return subprocess.run(
        compose_args(*args, project=project),
        cwd=ROOT,
        env=compose_environment(),
        check=check,
        text=True,
        capture_output=capture,
    )


def volume_name(project: str, suffix: str) -> str:
    return f"{project}_{suffix}"


def sha256_paths(paths: Iterable[Path]) -> str:
    hasher = hashlib.sha256()
    for path in sorted(paths):
        _hash_file(hasher, path, path.relative_to(ROOT).as_posix())
    return hasher.hexdigest()
