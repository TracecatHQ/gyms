"""Fast structural checks for the portable gym."""
from __future__ import annotations
import csv, json, subprocess
from . import config
from .dataset import validate_archive

def validate() -> None:
    lock = config.load_lock()
    if lock["gym"]["id"] != "002" or lock["gym"]["compose_project"] != config.PROJECT: raise RuntimeError("gym identity drift")
    validate_archive(count_records=True)
    with (config.ROOT / "data/alerts.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 34 or len({r["alert_id"] for r in rows}) != 34: raise RuntimeError("alert queue drift")
    json.loads((config.ROOT / "evals.json").read_text()); json.loads((config.ROOT / "agent-preset.json").read_text())
    forbidden = ("amazonaws.com/tracecat", "read_parquet")
    for path in [*config.ROOT.glob("*.md"), *config.ROOT.glob("skills/**/*.md")]:
        text = path.read_text().lower()
        if any(term in text for term in forbidden): raise RuntimeError(f"stale storage instruction in {path.relative_to(config.ROOT)}")
    dockerfile = (config.ROOT / "images/control/Dockerfile").read_text()
    if "assets" in dockerfile or ".zip" in dockerfile: raise RuntimeError("dataset must not be copied into an image")
    result = subprocess.run(config.compose_args("--profile", "bootstrap", "config"), cwd=config.ROOT,
                            env=config.compose_environment(), text=True, capture_output=True)
    if result.returncode: raise RuntimeError(f"Compose config failed: {result.stderr}")
    override = (config.ROOT / "compose.override.yml").read_text()
    mount = "assets/botsv3-20260904T130332Z-1-001.zip:/run/gym-data/botsv3.zip:ro"
    if override.count(mount) != 1 or "/run/gym-data/botsv3.zip" not in result.stdout:
        raise RuntimeError("dataset must have exactly one read-only runtime mount")
    print("[gym-002] Structural checks passed.")
