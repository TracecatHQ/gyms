"""Gym 002 command bindings."""

from __future__ import annotations


def dispatch(args):
    if args.command == "seed":
        from .seed import main

        return main()
    if args.command == "internal-seed-dataset":
        from .dataset import main

        return main()
    if args.command == "internal-reconcile":
        from .reconcile import reconcile, status

        (reconcile if args.mode == "reconcile" else status)()
        return 0
    if args.command == "internal-eval":
        from .evaluate import main

        values = ["--alert-id", args.alert_id] if args.alert_id else []
        return main(values)
    if args.command == "internal-reset-evals":
        from .reconcile import reset_managed_evaluations

        reset_managed_evaluations()
        return 0
    if args.command == "check":
        from .validate import validate

        validate()
        return 0
    from . import host

    if args.command == "init":
        host.init()
    elif args.command == "doctor":
        host.doctor()
    elif args.command == "build":
        if args.components:
            raise ValueError(
                "Gym 002 has only one control image; build takes no components"
            )
        host.build(force=args.force)
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
        if args.runs is not None:
            raise ValueError(
                "Gym 002 evaluates each selected case once; use --alert-id to select one"
            )
        host.evaluate(args.alert_id)
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
    elif args.command == "check-upstreams":
        host.check_upstreams()
    elif args.command == "update-upstreams":
        from gymctl.update_upstreams import update_upstreams

        update_upstreams()
    elif args.command == "update-dataset":
        host.update_dataset(args)
    elif args.command == "volume-digest":
        print(host.volume_digest(args.path))
    else:
        raise RuntimeError(f"Gym 002 does not support {args.command}")
    return 0
