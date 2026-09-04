"""Paths, immutable image references, and Compose invocation."""
from __future__ import annotations
import base64, hashlib, json, os, subprocess
from pathlib import Path

PROJECT = "tracecat-gym-002"
VOLUME_SUFFIXES = ("core-db", "temporal-db", "minio-data", "redis-data", "sandbox-cache")

def root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[2]

ROOT = root()
LOCK_PATH = ROOT / "gym.lock.json"

def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text())

def parse_env(path: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    source = path or ROOT / ".env"
    if source.is_file():
        for raw in source.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1); values[key] = value.strip().strip('"').strip("'")
    return values

def upstream_image(name: str) -> str:
    item = load_lock()["images"]["upstream"][name]
    return f"{item['source_ref']}@{item['digest']}"

def image_input_hash() -> str:
    hasher = hashlib.sha256()
    paths = list((ROOT / "src").rglob("*.py")) + list((ROOT / "data").glob("*.csv"))
    paths += [ROOT / name for name in ("images/control/Dockerfile", "agent-preset.json", "gym.lock.json", "ANALYST_INSTRUCTIONS.md")]
    for path in sorted(paths):
        hasher.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    return hasher.hexdigest()

def local_image() -> str:
    return f"{load_lock()['images']['local']['control']['repository']}:{image_input_hash()[:16]}"

def compose_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update({"GYM_ROOT": str(ROOT), "GYM_CONTROL_IMAGE": local_image(),
                "GYM_CADDYFILE_B64": base64.b64encode((ROOT / "upstream/tracecat/Caddyfile").read_bytes()).decode(),
                **{f"IMAGE_{name.upper()}": upstream_image(name) for name in load_lock()["images"]["upstream"]}})
    return env

def compose_args(*args: str) -> list[str]:
    env_file = ROOT / (".env" if (ROOT / ".env").is_file() else ".env.example")
    return ["docker", "compose", "--project-name", PROJECT, "--project-directory", str(ROOT), "--env-file", str(env_file),
            "-f", str(ROOT / "upstream/tracecat/docker-compose.yml"), "-f", str(ROOT / "compose.override.yml"), *args]

def run_compose(*args: str, check: bool = True, capture: bool = False):
    return subprocess.run(compose_args(*args), cwd=ROOT, env=compose_environment(), check=check, text=True, capture_output=capture)
