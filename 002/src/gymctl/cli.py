"""Single command interface for Gym 002."""
from __future__ import annotations
import argparse, sys

def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="gymctl"); sub = command.add_subparsers(dest="command", required=True)
    for name in ("init", "doctor", "build", "up", "info", "status", "reconcile", "down", "check", "seed", "internal-seed-dataset"): sub.add_parser(name)
    logs = sub.add_parser("logs"); logs.add_argument("service", nargs="?")
    reset = sub.add_parser("reset"); reset.add_argument("--confirm")
    internal = sub.add_parser("internal-reconcile"); internal.add_argument("mode", choices=("reconcile", "status"), nargs="?", default="reconcile")
    return command

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "seed":
            from .seed import main as fn
            return fn()
        if args.command == "internal-seed-dataset":
            from .dataset import main as fn
            return fn()
        if args.command == "internal-reconcile":
            from .reconcile import reconcile, status
            (reconcile if args.mode == "reconcile" else status)(); return 0
        if args.command == "check":
            from .validate import validate
            validate(); return 0
        from . import host
        fn = getattr(host, args.command)
        if args.command == "logs": fn(args.service)
        elif args.command == "reset": fn(args.confirm)
        else: fn()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 1
    return 0
