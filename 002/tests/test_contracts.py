import json
from pathlib import Path


def test_preset_tools_and_evals_contract():
    root = Path(__file__).resolve().parents[1]
    preset = json.loads((root / "agent-preset.json").read_text())
    assert "core.duckdb.execute_sql" in preset["actions"]
    assert {"core.cases.get_case", "core.cases.search_cases", "core.cases.update_case", "core.cases.create_comment", "core.cases.add_case_tag"} <= set(preset["actions"])
    assert preset["enable_internet_access"] is False
    evals = json.loads((root / "evals.json").read_text())
    assert evals
