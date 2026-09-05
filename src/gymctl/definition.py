"""Explicit contract every gym exposes to the shared runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class GymDefinition:
    gym_id: str
    root: Path
    compose_project: str
    volume_suffixes: tuple[str, ...]
    host_port: int
    legacy_compose_project: str | None = None
    prefer_gym_upstream_images: bool = False

    def __post_init__(self) -> None:
        root = self.root.resolve()
        object.__setattr__(self, "root", root)
        if not self.gym_id.isdigit():
            raise ValueError("gym definition ID must be numeric")
        if not self.compose_project or self.host_port < 1:
            raise ValueError("gym definition has invalid Compose identity")
        if len(set(self.volume_suffixes)) != len(self.volume_suffixes):
            raise ValueError("gym definition has duplicate volume suffixes")

    @property
    def repo_root(self) -> Path:
        return self.root.parent

    @property
    def lock_path(self) -> Path:
        return self.root / "gym.lock.json"

    @property
    def platform_lock_path(self) -> Path:
        return self.repo_root / "platform.lock.json"

    def load_lock(self) -> dict:
        return json.loads(self.lock_path.read_text())

    def load_platform_lock(self) -> dict:
        return json.loads(self.platform_lock_path.read_text())
