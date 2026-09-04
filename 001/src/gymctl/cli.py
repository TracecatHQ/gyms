"""Single command interface for all Gym 001 operations."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="gymctl")
    subparsers = command.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init")
    subparsers.add_parser("doctor")
    build = subparsers.add_parser("build")
    build.add_argument("components", nargs="*", choices=("splunk", "control"))
    build.add_argument("--force", action="store_true")
    subparsers.add_parser("migrate")
    subparsers.add_parser("up")
    subparsers.add_parser("info")
    subparsers.add_parser("status")
    subparsers.add_parser("wait")
    subparsers.add_parser("reconcile")
    evaluate = subparsers.add_parser("eval")
    evaluate.add_argument("--runs", type=int, default=1)
    logs = subparsers.add_parser("logs")
    logs.add_argument("service", nargs="?")
    subparsers.add_parser("down")
    clean_restart = subparsers.add_parser("clean-restart")
    clean_restart.add_argument("--confirm")
    reset = subparsers.add_parser("reset")
    reset.add_argument("--confirm")
    rotate = subparsers.add_parser("rotate-license")
    rotate.add_argument("--file", required=True, type=Path)
    subparsers.add_parser("check")
    subparsers.add_parser("check-upstreams")
    update_dataset = subparsers.add_parser("update-dataset")
    update_dataset.add_argument("--ref", required=True)
    subparsers.add_parser("update-upstreams")
    subparsers.add_parser("seed")
    subparsers.add_parser("mcp-proxy")
    internal_reconcile = subparsers.add_parser("internal-reconcile")
    internal_reconcile.add_argument("mode", choices=("reconcile", "status"), default="reconcile", nargs="?")
    internal_eval = subparsers.add_parser("internal-eval")
    internal_eval.add_argument("--runs", type=int)
    volume = subparsers.add_parser("volume-digest")
    volume.add_argument("path", type=Path)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "seed":
            from .seed import main as seed_main
            return seed_main()
        if args.command == "mcp-proxy":
            from .mcp_proxy import main as proxy_main
            proxy_main()
            return 0
        if args.command == "internal-reconcile":
            from .reconcile import reconcile, status
            (reconcile if args.mode == "reconcile" else status)()
            return 0
        if args.command == "internal-eval":
            from .evaluate import main as eval_main
            values = ["--runs", str(args.runs)] if args.runs is not None else []
            return eval_main(values)
        from . import host
        if args.command == "init": host.init_env()
        elif args.command == "doctor": host.doctor(allow_legacy_ports=True)
        elif args.command == "build": host.build(tuple(args.components) or ("splunk", "control"), force=args.force)
        elif args.command == "migrate": host.migrate()
        elif args.command == "up": host.up()
        elif args.command == "info": host.info()
        elif args.command == "status": host.status()
        elif args.command == "wait": host.wait()
        elif args.command == "reconcile": host.reconcile()
        elif args.command == "eval": host.evaluate(args.runs)
        elif args.command == "logs": host.logs(args.service)
        elif args.command == "down": host.down()
        elif args.command == "clean-restart": host.clean_restart(args.confirm)
        elif args.command == "reset": host.reset(args.confirm)
        elif args.command == "rotate-license": host.rotate_license(args.file.resolve())
        elif args.command == "check-upstreams": host.check_upstreams()
        elif args.command == "check":
            from .validate import validate
            validate()
        elif args.command == "update-dataset":
            from .update_dataset import update_dataset
            update_dataset(args.ref)
        elif args.command == "update-upstreams":
            from .update_upstreams import update_upstreams
            update_upstreams()
        elif args.command == "volume-digest": print(host.volume_digest(args.path))
        else: raise RuntimeError(f"unhandled command {args.command}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0
