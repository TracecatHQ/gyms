"""Refresh pristine Tracecat snapshots and all OCI image-index digests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from typing import Any

from . import config


REPOSITORY = "TracecatHQ/tracecat"
SERVICE_KEYS = {
    "caddy": "caddy", "api": "tracecat", "ui": "tracecat_ui",
    "postgres_db": "postgres", "temporal_postgres_db": "temporal_postgres",
    "temporal": "temporal", "temporal_ui": "temporal_ui", "minio": "minio", "redis": "redis",
}


def _request(url: str) -> bytes:
    headers = {"User-Agent": "tracecat-gyms/001"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return response.read()


def _json(url: str) -> Any:
    return json.loads(_request(url))


def _env(raw: bytes) -> dict[str, str]:
    return {match.group(1): match.group(2).strip().strip('"').strip("'") for line in raw.decode().splitlines() if (match := re.match(r"^([A-Z0-9_]+)=(.*)$", line))}


def _resolve(value: str, env: dict[str, str]) -> str:
    return re.sub(r"\$\{([A-Z0-9_]+)(?::-([^}]+))?\}", lambda match: env.get(match.group(1)) or match.group(2) or "", value.strip().strip('"').strip("'"))


def _images(compose: bytes, env_raw: bytes) -> dict[str, str]:
    environment, current, found = _env(env_raw), None, {}
    for line in compose.decode().splitlines():
        if match := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line): current = match.group(1)
        elif current and (match := re.match(r"^    image:\s*(.+?)\s*$", line)): found[current] = _resolve(match.group(1), environment)
    return found


def _digest(reference: str) -> str:
    result = subprocess.run(["docker", "buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest}}"], check=True, text=True, capture_output=True)
    digest = json.loads(result.stdout).get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError(f"registry returned no digest for {reference}")
    return digest


def update_upstreams() -> None:
    releases = [item for item in _json(f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=50") if not item.get("draft")]
    latest = max(releases, key=lambda item: item["published_at"])
    tag = str(latest["tag_name"])
    ref = _json(f"https://api.github.com/repos/{REPOSITORY}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")["object"]
    tag_object = str(ref["sha"])
    if ref["type"] == "tag": ref = _json(ref["url"])["object"]
    if ref["type"] != "commit": raise RuntimeError("Tracecat tag does not resolve to a commit")
    base = f"https://raw.githubusercontent.com/{REPOSITORY}/{urllib.parse.quote(tag, safe='')}"
    compose, caddy, env = _request(f"{base}/docker-compose.yml"), _request(f"{base}/Caddyfile"), _request(f"{base}/.env.example")
    discovered = _images(compose, env)
    lock = config.load_lock()
    upstream = {}
    for service, key in SERVICE_KEYS.items():
        reference = discovered[service]
        upstream[key] = {"source_ref": reference, "digest": _digest(reference)}
    splunk_ref = lock["images"]["upstream"]["splunk"]["source_ref"]
    upstream["splunk"] = {"source_ref": splunk_ref, "digest": _digest(splunk_ref)}
    lock["sources"]["tracecat"] = {
        "repository": REPOSITORY, "tag": tag, "tag_object": tag_object,
        "commit": str(ref["sha"]), "published_at": latest["published_at"],
        "compose_sha256": hashlib.sha256(compose).hexdigest(),
        "caddyfile_sha256": hashlib.sha256(caddy).hexdigest(),
    }
    lock["images"]["upstream"] = upstream
    (config.ROOT / "upstream/tracecat/docker-compose.yml").write_bytes(compose)
    (config.ROOT / "upstream/tracecat/Caddyfile").write_bytes(caddy)
    config.LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"Tracecat snapshots and image digests updated to {tag}; review the Git diff.")
