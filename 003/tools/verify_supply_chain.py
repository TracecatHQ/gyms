#!/usr/bin/env python3
"""Re-check image metadata against official registries without pulling images."""

from __future__ import annotations

import json
import urllib.request
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "tracecat-gym-003/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main() -> int:
    lock = json.loads((ROOT / "gym.lock.json").read_text())
    supply = lock["supply_chain"]
    cutoff = date.fromisoformat(supply["image_cooldown_cutoff"])
    checked = 0
    for name, item in sorted(supply["verified_images"].items()):
        url = item.get("registry_metadata_url")
        if not url:
            # GHCR release images are tied to the signed/pinned Tracecat release
            # record in platform.lock.json and verified locally by exact digest.
            continue
        metadata = fetch_json(url)
        if metadata.get("digest") != item["digest"]:
            raise RuntimeError(f"{name}: registry digest changed")
        published = date.fromisoformat(metadata["last_updated"][:10])
        if published.isoformat() != item["published_at"][:10]:
            raise RuntimeError(f"{name}: registry publication date changed")
        if published > cutoff:
            raise RuntimeError(f"{name}: image has not completed the seven-day cooldown")
        arm64 = [
            image for image in metadata.get("images", [])
            if image.get("os") == "linux" and image.get("architecture") == "arm64"
        ]
        if not arm64:
            raise RuntimeError(f"{name}: registry no longer reports linux/arm64")
        platform_digest = item.get("platform_digest")
        if platform_digest and platform_digest not in {
            image.get("digest") for image in arm64
        }:
            raise RuntimeError(f"{name}: recorded ARM64 child digest changed")
        checked += 1
    print(f"[gym-003] verified {checked} old-enough image records against official registries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
