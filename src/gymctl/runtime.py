"""Gym discovery and plugin loading."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from types import ModuleType


class GymRuntimeError(RuntimeError):
    pass


def discover_gym_root() -> Path:
    configured = os.environ.get("GYM_ROOT")
    if configured:
        candidate = Path(configured).resolve()
        if (candidate / "src/gym_plugin").is_dir():
            return candidate
        raise GymRuntimeError(f"GYM_ROOT has no gym plugin: {candidate}")
    for candidate in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if candidate.name.isdigit() and (candidate / "src/gym_plugin").is_dir():
            return candidate
    raise GymRuntimeError("run gymctl from a numeric gym directory or set GYM_ROOT")


def load_plugin() -> ModuleType:
    root = discover_gym_root()
    os.environ["GYM_ROOT"] = str(root)
    source = str(root / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    plugin = importlib.import_module("gym_plugin.plugin")
    if not callable(getattr(plugin, "dispatch", None)):
        raise GymRuntimeError(f"gym plugin at {root} does not export dispatch(args)")
    return plugin
