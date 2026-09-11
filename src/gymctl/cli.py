"""Stable command surface shared by all gyms."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .runtime import load_plugin


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="gymctl")
    sub = command.add_subparsers(dest="command", required=True)
    for name in (
        "init",
        "doctor",
        "migrate",
        "up",
        "info",
        "status",
        "wait",
        "reconcile",
        "down",
        "restart",
        "check",
        "check-upstreams",
        "update-upstreams",
        "seed",
        "internal-seed-dataset",
        "mcp-proxy",
        "internal-test-api",
        "internal-collector",
        "internal-scenario-reset",
    ):
        sub.add_parser(name)
    build = sub.add_parser("build")
    build.add_argument("components", nargs="*")
    build.add_argument("--force", action="store_true")
    evaluate = sub.add_parser("eval")
    evaluate.add_argument("--runs", type=int)
    evaluate.add_argument("--alert-id")
    evaluate.add_argument("--via-workflow", action="store_true")
    rescore = sub.add_parser("rescore")
    rescore.add_argument("--eval-id", required=True)
    rescore.add_argument("--alert-id")
    internal_rescore = sub.add_parser("internal-rescore")
    internal_rescore.add_argument("--eval-id", required=True)
    internal_rescore.add_argument("--alert-id")
    internal_eval = sub.add_parser("internal-eval")
    internal_eval.add_argument("--runs", type=int)
    internal_eval.add_argument("--alert-id")
    internal_eval.add_argument("--via-workflow", action="store_true")
    sub.add_parser("internal-reset-evals")
    logs = sub.add_parser("logs")
    logs.add_argument("service", nargs="?")
    for name in ("clean-restart", "reset-evals", "reset"):
        destructive = sub.add_parser(name)
        destructive.add_argument("--confirm")
    scenario_reset = sub.add_parser("scenario-reset")
    scenario_reset.add_argument("--confirm")
    rotate = sub.add_parser("rotate-license")
    rotate.add_argument("--file", required=True, type=Path)
    update_dataset = sub.add_parser("update-dataset")
    update_dataset.add_argument("--ref")
    update_dataset.add_argument("--writeup-html", type=Path)
    update_dataset.add_argument("--duckdb")
    update_dataset.add_argument("--data-glob")
    update_dataset.add_argument("--archive", type=Path)
    internal = sub.add_parser("internal-reconcile")
    internal.add_argument(
        "mode", choices=("reconcile", "status"), default="reconcile", nargs="?"
    )
    volume = sub.add_parser("volume-digest")
    volume.add_argument("path", type=Path)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = load_plugin().dispatch(args)
        return int(result or 0)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
