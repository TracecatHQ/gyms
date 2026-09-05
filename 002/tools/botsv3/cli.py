"""Command-line compiler and read-only corpus contract audit."""

from __future__ import annotations

import argparse
from pathlib import Path

from .evidence import resolve_evidence
from .model import load_specs
from .render import json_text, render, write_outputs
from .validate import validate_outputs


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--archive", required=True, type=Path)
    command.add_argument("--specs", required=True, type=Path)
    command.add_argument("--output-root", required=True, type=Path)
    command.add_argument("--check", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    cases = load_specs(args.specs)
    resolved = resolve_evidence(args.archive, cases)
    scenario, contracts = render(cases, resolved)
    validate_outputs(scenario, contracts)
    if args.check:
        expected = {
            args.output_root / "benchmark/scenario.json": json_text(scenario),
            args.output_root / "benchmark/evals/cases.json": json_text(contracts),
        }
        drift = [
            str(path)
            for path, text in expected.items()
            if not path.is_file() or path.read_text() != text
        ]
        if drift:
            raise RuntimeError(f"generated benchmark artifacts are stale: {drift}")
        print(
            f"BOTSv3 corpus contract READY: {len(cases)} cases; generated artifacts exact"
        )
    else:
        write_outputs(args.output_root, scenario, contracts)
        print(f"wrote {len(cases)} audited cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
