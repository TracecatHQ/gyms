"""Refresh pristine Tracecat snapshots and all OCI image-index digests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from typing import Any

from pathlib import Path


REPOSITORY = "TracecatHQ/tracecat"
SERVICE_KEYS = {
    "caddy": "caddy",
    "api": "tracecat",
    "ui": "tracecat_ui",
    "postgres_db": "postgres",
    "temporal_postgres_db": "temporal_postgres",
    "temporal": "temporal",
    "temporal_ui": "temporal_ui",
    "minio": "minio",
    "redis": "redis",
}


def _request(url: str) -> bytes:
    headers = {"User-Agent": "tracecat-gyms"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers), timeout=30
    ) as response:
        return response.read()


def _json(url: str) -> Any:
    return json.loads(_request(url))


def _env(raw: bytes) -> dict[str, str]:
    return {
        match.group(1): match.group(2).strip().strip('"').strip("'")
        for line in raw.decode().splitlines()
        if (match := re.match(r"^([A-Z0-9_]+)=(.*)$", line))
    }


def _resolve(value: str, env: dict[str, str]) -> str:
    return re.sub(
        r"\$\{([A-Z0-9_]+)(?::-([^}]+))?\}",
        lambda match: env.get(match.group(1)) or match.group(2) or "",
        value.strip().strip('"').strip("'"),
    )


def _images(compose: bytes, env_raw: bytes) -> dict[str, str]:
    environment, current, found = _env(env_raw), None, {}
    for line in compose.decode().splitlines():
        if match := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line):
            current = match.group(1)
        elif current and (match := re.match(r"^    image:\s*(.+?)\s*$", line)):
            found[current] = _resolve(match.group(1), environment)
    return found


def _digest(reference: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            reference,
            "--format",
            "{{json .Manifest}}",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    digest = json.loads(result.stdout).get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError(f"registry returned no digest for {reference}")
    return digest


def check_upstreams(extra_images: dict[str, dict[str, str]] | None = None) -> None:
    """Fail closed when the shared Tracecat pin or an OCI digest has drifted."""
    repo_root = Path(__file__).resolve().parents[2]
    lock = json.loads((repo_root / "platform.lock.json").read_text())
    allow_stale = os.environ.get("ALLOW_STALE_UPSTREAM") == "1"
    try:
        releases = [
            item
            for item in _json(
                f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=50"
            )
            if not item.get("draft")
        ]
        latest = max(releases, key=lambda item: item["published_at"])
        if latest["tag_name"] != lock["tracecat"]["tag"]:
            raise RuntimeError(
                f"Tracecat is pinned to {lock['tracecat']['tag']}, but the latest "
                f"published release is {latest['tag_name']}; run just update-upstreams"
            )
        images = {**lock["images"], **(extra_images or {})}
        for name, item in images.items():
            observed = _digest(item["source_ref"])
            if observed != item["digest"]:
                raise RuntimeError(
                    f"upstream image moved for {name}: expected {item['digest']}, "
                    f"got {observed}"
                )
    except Exception as exc:
        if not allow_stale:
            raise RuntimeError(f"upstream check failed closed: {exc}") from exc
        print(
            f"WARNING: upstream verification bypassed by ALLOW_STALE_UPSTREAM=1: {exc}"
        )
    else:
        print(f"Upstreams are current and immutable at {lock['tracecat']['tag']}.")


def _gym_directories(repo_root: Path) -> list[Path]:
    return [
        path
        for path in sorted(repo_root.iterdir())
        if path.is_dir()
        and path.name.isdigit()
        and (path / "gym.lock.json").is_file()
        and (path / "src/gym_plugin/config.py").is_file()
    ]


def _refresh_gym_locks(repo_root: Path) -> None:
    gyms = _gym_directories(repo_root)
    for gym_root in gyms:
        lock_path = gym_root / "gym.lock.json"
        lock = json.loads(lock_path.read_text())
        for item in lock.get("images", {}).get("upstream", {}).values():
            item["digest"] = _digest(str(item["source_ref"]))
        lock_path.write_text(json.dumps(lock, indent=2) + "\n")

    script = """
import json
import inspect
from gym_plugin import config

lock = config.load_lock()
function = config.image_input_hash
components = lock.get("images", {}).get("local", {})
if len(inspect.signature(function).parameters) == 0:
    hashes = {name: function() for name in components}
else:
    hashes = {name: function(name) for name in components}
print(json.dumps(hashes, sort_keys=True))
"""
    for gym_root in gyms:
        environment = os.environ.copy()
        environment.update(
            {
                "GYM_ROOT": str(gym_root),
                "PYTHONPATH": f"{repo_root / 'src'}:{gym_root / 'src'}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=gym_root,
            env=environment,
            check=True,
            text=True,
            capture_output=True,
        )
        hashes = json.loads(result.stdout)
        lock_path = gym_root / "gym.lock.json"
        lock = json.loads(lock_path.read_text())
        for name, digest in hashes.items():
            lock["images"]["local"][name]["input_sha256"] = digest
        lock_path.write_text(json.dumps(lock, indent=2) + "\n")


def update_upstreams() -> None:
    releases = [
        item
        for item in _json(
            f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=50"
        )
        if not item.get("draft")
    ]
    latest = max(releases, key=lambda item: item["published_at"])
    tag = str(latest["tag_name"])
    ref = _json(
        f"https://api.github.com/repos/{REPOSITORY}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
    )["object"]
    tag_object = str(ref["sha"])
    if ref["type"] == "tag":
        ref = _json(ref["url"])["object"]
    if ref["type"] != "commit":
        raise RuntimeError("Tracecat tag does not resolve to a commit")
    base = f"https://raw.githubusercontent.com/{REPOSITORY}/{urllib.parse.quote(tag, safe='')}"
    compose, caddy, env = (
        _request(f"{base}/docker-compose.yml"),
        _request(f"{base}/Caddyfile"),
        _request(f"{base}/.env.example"),
    )
    discovered = _images(compose, env)
    repo_root = Path(__file__).resolve().parents[2]
    lock_path = repo_root / "platform.lock.json"
    lock = json.loads(lock_path.read_text())
    upstream = {}
    for service, key in SERVICE_KEYS.items():
        reference = discovered[service]
        upstream[key] = {"source_ref": reference, "digest": _digest(reference)}
    lock["tracecat"] = {
        "classification": "upstream-verbatim",
        "repository": REPOSITORY,
        "tag": tag,
        "tag_object": tag_object,
        "commit": str(ref["sha"]),
        "published_at": latest["published_at"],
        "compose_sha256": hashlib.sha256(compose).hexdigest(),
        "caddyfile_sha256": hashlib.sha256(caddy).hexdigest(),
    }
    lock["images"] = upstream
    (repo_root / "upstream/tracecat/docker-compose.yml").write_bytes(compose)
    (repo_root / "upstream/tracecat/Caddyfile").write_bytes(caddy)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")
    _refresh_gym_locks(repo_root)
    print(
        f"Tracecat snapshots, image digests, and derived gym image locks updated to {tag}; review the Git diff."
    )
