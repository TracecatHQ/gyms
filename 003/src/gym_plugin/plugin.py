"""Gym 003 command bindings."""

from __future__ import annotations


def dispatch(args):
    if args.command == "seed":
        from gymctl.seed import main
        return main()
    if args.command == "internal-collector":
        from .collector import main
        main()
        return 0
    if args.command == "internal-scenario-reset":
        from .host import internal_scenario_reset
        internal_scenario_reset()
        return 0
    if args.command == "internal-reconcile":
        from .reconcile import reconcile, status
        (reconcile if args.mode == "reconcile" else status)()
        return 0
    if args.command == "internal-eval":
        import json
        import os
        from pathlib import Path

        from .acceptance import evaluate
        from .waf import WAFClient

        waf = WAFClient.from_env()
        context = {
            "scenario": "supplier-intake",
            "ingress": "http://bunkerweb:8080",
            "host": "supplier.intake.test",
            "evidence_dir": Path(os.environ.get("GYM_EVAL_RESULTS", "/opt/gym/eval-results")),
            "state_dir": Path("/var/lib/gym/state"),
            "timeout": 60,
            "waf_client": waf,
            "failure_guards_runner": waf.run_failure_guards,
        }
        result = evaluate(context)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("passed") is True else 1
    if args.command == "check":
        from .validate import validate
        validate()
        return 0

    from . import host
    handlers = {
        "init": lambda: host.init(),
        "doctor": lambda: host.doctor(),
        "build": lambda: host.build(tuple(args.components), force=args.force),
        "migrate": lambda: host.migrate(),
        "up": lambda: host.up(),
        "info": lambda: host.info(),
        "status": lambda: host.status(),
        "wait": lambda: host.wait(),
        "reconcile": lambda: host.reconcile(),
        "eval": lambda: host.evaluate(),
        "logs": lambda: host.logs(args.service),
        "down": lambda: host.down(),
        "restart": lambda: host.restart(),
        "clean-restart": lambda: host.clean_restart(args.confirm),
        "reset": lambda: host.reset(args.confirm),
        "scenario-reset": lambda: host.scenario_reset(args.confirm),
        "check-upstreams": lambda: host.check_upstreams(),
        "update-upstreams": lambda: host.update_upstreams(),
        "volume-digest": lambda: print(host.volume_digest(args.path)),
    }
    if args.command not in handlers:
        raise RuntimeError(f"Gym 003 does not support {args.command}")
    result = handlers[args.command]()
    return int(result or 0)
