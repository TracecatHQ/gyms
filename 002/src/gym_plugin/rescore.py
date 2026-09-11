#!/usr/bin/env python3
"""Re-score a completed Gym 002 evaluation from its saved artifacts.

Scoring is a pure function of the investigation artifacts, so a scorer fix does
not require re-running investigators. This replays ``tool-calls.json`` and
``case-after.json`` through the current objective scorer and writes a new
result directory, leaving the source evaluation untouched.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gymctl import agents

from .eval_contracts import (
    RESULTS_ROOT,
    SEMANTIC_GATE_KEY,
    EvalError,
    load_configuration,
    load_contracts,
)
from .eval_objective import deterministic_determinations
from .evaluate import combine_determinations, render_report


def log(message: str) -> None:
    print(f"[gym-002-rescore] {message}", flush=True)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvalError(f"cannot read {path.name}: {exc}") from exc


def saved_semantic(case_dir: Path, config: dict[str, Any]) -> str:
    """Recover the grader's verdict from the source run's determinations."""
    gate_text = config["validation_gates"][SEMANTIC_GATE_KEY]
    rows = _read_json(case_dir / "determinations.json").get("determinations") or []
    for row in rows:
        if row.get("validation_gate") == gate_text:
            return str(row["determination"])
    raise EvalError(f"{case_dir.name}: source run has no semantic determination")


def rescore(
    eval_id: str, alert_id: str | None = None, results_root: Path | None = None
) -> int:
    root = results_root or RESULTS_ROOT
    source = root / eval_id
    if not source.is_dir():
        raise EvalError(f"evaluation {eval_id} not found under {root}")
    config = load_configuration()
    contracts = {row["alert_id"]: row for row in load_contracts(config)}
    escalation_assignee = agents.required_env("TRACEcat_TENANT_EMAIL")
    source_results = _read_json(source / "results.json")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = root / f"{eval_id}-rescore-{stamp}"
    target.mkdir(parents=True, mode=0o700)

    rescored: list[dict[str, Any]] = []
    changed: list[str] = []
    for state in source_results["cases"]:
        case_id = str(state["alert_id"])
        if alert_id and case_id != alert_id:
            continue
        case_dir = next(
            (d for d in sorted(source.iterdir()) if d.is_dir() and _matches(d, case_id)),
            None,
        )
        if case_dir is None or state.get("status") == "error":
            log(f"{case_id}: skipped (no scorable artifacts)")
            rescored.append({**state, "rescore": "skipped"})
            continue
        contract = contracts.get(case_id)
        if contract is None:
            raise EvalError(f"{case_id} is not a known evaluation case")
        calls = _read_json(case_dir / "tool-calls.json")
        after = _read_json(case_dir / "case-after.json")
        objective, observations = deterministic_determinations(
            contract, calls, after, escalation_assignee=escalation_assignee
        )
        semantic = {
            "determinations": [{"determination": saved_semantic(case_dir, config)}]
        }
        determinations = combine_determinations(config, contract, objective, semantic)
        passed = all(row["determination"] == "met" for row in determinations)
        out_dir = target / case_dir.name
        out_dir.mkdir(mode=0o700)
        agents.write_json(out_dir / "objective-observations.json", observations)
        agents.write_json(
            out_dir / "determinations.json", {"determinations": determinations}
        )
        new_state = {
            **state,
            "status": "passed" if passed else "failed",
            "determinations": determinations,
            "rescored_at": datetime.now(UTC).isoformat(),
        }
        agents.write_json(out_dir / "state.json", new_state)
        rescored.append(new_state)
        if new_state["status"] != state.get("status"):
            changed.append(f"{case_id}: {state.get('status')} -> {new_state['status']}")
        log(f"{case_id}: {state.get('status')} -> {new_state['status']}")

    result = {
        "metadata": {
            **source_results["metadata"],
            "rescored_from": eval_id,
            "rescored_at": datetime.now(UTC).isoformat(),
            "semantic_gate_source": "reused from source run (grader not re-run)",
        },
        "cases": rescored,
        "passed": all(row["status"] == "passed" for row in rescored),
    }
    agents.write_json(target / "results.json", result)
    (target / "report.md").write_text(render_report(result))
    scored = [r for r in rescored if r.get("rescore") != "skipped"]
    log(
        f"rescored {len(scored)} case(s); "
        f"{sum(1 for r in scored if r['status'] == 'passed')} passed; "
        f"{len(changed)} changed"
    )
    for line in changed:
        log(f"  changed {line}")
    log(f"rescore report: {target / 'report.md'}")
    return 0 if result["passed"] else 1


def _matches(case_dir: Path, alert_id: str) -> bool:
    contract_path = case_dir / "evaluation-contract.json"
    if not contract_path.is_file():
        return False
    try:
        return json.loads(contract_path.read_text()).get("alert_id") == alert_id
    except (OSError, json.JSONDecodeError):
        return False


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-id", required=True)
    parser.add_argument("--alert-id")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return rescore(args.eval_id, args.alert_id)
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
