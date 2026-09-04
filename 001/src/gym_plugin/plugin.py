"""Gym 001 command bindings."""

from __future__ import annotations


def dispatch(args):
    if args.command == "seed":
        from .seed import main

        return main()
    if args.command == "mcp-proxy":
        from .mcp_proxy import main

        main()
        return 0
    if args.command == "internal-reconcile":
        from .reconcile import reconcile, status

        (reconcile if args.mode == "reconcile" else status)()
        return 0
    if args.command == "internal-eval":
        from .evaluate import main

        values = ["--runs", str(args.runs)] if args.runs is not None else []
        return main(values)
    if args.command == "internal-reset-evals":
        from .reconcile import reset_managed_evaluations

        reset_managed_evaluations()
        return 0
    from . import host

    if args.command == "init":
        host.init_env()
    elif args.command == "doctor":
        host.doctor(allow_legacy_ports=True)
    elif args.command == "build":
        host.build(tuple(args.components) or ("splunk", "control"), force=args.force)
    elif args.command == "migrate":
        host.migrate()
    elif args.command == "up":
        host.up()
    elif args.command == "info":
        host.info()
    elif args.command == "status":
        host.status()
    elif args.command == "wait":
        host.wait()
    elif args.command == "reconcile":
        host.reconcile()
    elif args.command == "eval":
        if args.alert_id:
            raise ValueError("Gym 001 eval does not accept --alert-id")
        host.evaluate(args.runs if args.runs is not None else 1)
    elif args.command == "logs":
        host.logs(args.service)
    elif args.command == "down":
        host.down()
    elif args.command == "restart":
        host.down()
        host.up()
    elif args.command == "clean-restart":
        host.clean_restart(args.confirm)
    elif args.command == "reset-evals":
        host.reset_evals(args.confirm)
    elif args.command == "reset":
        host.reset(args.confirm)
    elif args.command == "rotate-license":
        host.rotate_license(args.file.resolve())
    elif args.command == "check-upstreams":
        host.check_upstreams()
    elif args.command == "check":
        from .validate import validate

        validate()
    elif args.command == "update-dataset":
        if not args.ref:
            raise ValueError("Gym 001 update-dataset requires --ref")
        from .update_dataset import update_dataset

        update_dataset(args.ref)
    elif args.command == "update-upstreams":
        from gymctl.update_upstreams import update_upstreams

        update_upstreams()
    elif args.command == "volume-digest":
        print(host.volume_digest(args.path))
    else:
        raise RuntimeError(f"Gym 001 does not support {args.command}")
    return 0
