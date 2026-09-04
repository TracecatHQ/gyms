from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from gymctl import reconcile
from gymctl.scenario import alert_case_payload, load_scenario


ROOT = Path(__file__).parents[2]


class FakeTracecat:
    def __init__(self) -> None:
        self.cases: list[dict[str, Any]] = []
        self.tables: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.table_creates = 0
        self.row_creates = 0

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        **_: Any,
    ) -> Any:
        parts = url.strip("/").split("/")
        if method == "GET" and parts[-2:] == ["cases", "search"]:
            summary = params["search_term"]
            return {
                "items": [
                    {"id": case["id"], "summary": case["summary"]}
                    for case in self.cases
                    if case["summary"] == summary
                ]
            }
        if method == "POST" and parts[-1] == "cases":
            self.cases.append(
                {"id": f"case-{len(self.cases) + 1}", "short_id": "CASE-0001", **deepcopy(json_body)}
            )
            return None
        if "cases" in parts and parts[-1].startswith("case-"):
            case = next(row for row in self.cases if row["id"] == parts[-1])
            if method == "GET":
                return deepcopy(case)
            if method == "PATCH":
                case.update(deepcopy(json_body))
                return None
        if method == "GET" and parts[-1] == "tables":
            return [
                {"id": table["id"], "name": table["name"]}
                for table in self.tables
            ]
        if method == "POST" and parts[-1] == "tables":
            self.table_creates += 1
            self.tables.append(
                {
                    "id": f"table-{self.table_creates}",
                    "name": json_body["name"],
                    "columns": deepcopy(json_body["columns"]),
                    "rows": [],
                }
            )
            return None
        if "tables" in parts:
            table_index = parts.index("tables") + 1
            table_id = parts[table_index]
            table = next((row for row in self.tables if row["id"] == table_id), None)
            if method == "DELETE" and parts[-1] == table_id:
                self.tables = [row for row in self.tables if row["id"] != table_id]
                self.links = [row for row in self.links if row["table_id"] != table_id]
                return None
            if table is None:
                raise AssertionError(f"unknown table {table_id}")
            if method == "GET" and parts[-1] == table_id:
                return deepcopy(table)
            if method == "GET" and parts[-1] == "rows":
                assert params == {
                    "limit": 100,
                    "order_by": "created_at",
                    "sort": "asc",
                }
                return {"items": deepcopy(table["rows"])}
            if method == "POST" and parts[-1] == "rows":
                self.row_creates += 1
                table["rows"].append(
                    {"id": f"row-{self.row_creates}", **deepcopy(json_body["data"])}
                )
                return None
        if method == "GET" and parts[-1] == "rows" and "cases" in parts:
            table_id = params["table_id"]
            return {
                "items": [
                    deepcopy(row)
                    for row in self.links
                    if row["table_id"] == table_id
                ]
            }
        if method == "DELETE" and "cases" in parts and "rows" in parts:
            table_id, row_id = parts[-2:]
            self.links = [
                row
                for row in self.links
                if not (row["table_id"] == table_id and row["row_id"] == row_id)
            ]
            return None
        raise AssertionError(f"unexpected request: {method} {url}")


@pytest.fixture
def source() -> dict[str, Any]:
    return load_scenario(ROOT / "benchmark/scenario.json")


@pytest.fixture
def fake(monkeypatch: Any) -> FakeTracecat:
    client = FakeTracecat()

    def request_json(
        passed_client: FakeTracecat, method: str, url: str, **kwargs: Any
    ) -> Any:
        assert passed_client is client
        return client.request(method, url, **kwargs)

    monkeypatch.setattr(reconcile, "request_json", request_json)
    return client


def test_case_and_table_creation_is_idempotent_and_rows_are_individual(
    fake: FakeTracecat, source: dict[str, Any]
) -> None:
    alert_case = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    table = reconcile.reconcile_validation_table(
        fake, "workspace-1", alert_case["id"], source, repair=True
    )
    assert {key: alert_case[key] for key in alert_case_payload(source)} == (
        alert_case_payload(source)
    )
    assert table["name"] == "validation_gates"
    assert fake.tables[0]["rows"] == [
        {"id": f"row-{index}", **row}
        for index, row in enumerate(source["validation_gates"], start=1)
    ]
    assert fake.table_creates == 1
    assert fake.row_creates == 17

    same_case = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    same_table = reconcile.reconcile_validation_table(
        fake, "workspace-1", same_case["id"], source, repair=True
    )
    assert same_case["id"] == alert_case["id"]
    assert same_table["id"] == table["id"]
    assert fake.table_creates == 1
    assert fake.row_creates == 17


def test_case_drift_is_repaired_and_duplicate_cases_are_refused(
    fake: FakeTracecat, source: dict[str, Any]
) -> None:
    alert_case = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    fake.cases[0]["severity"] = "critical"
    repaired = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    assert repaired["severity"] == "unknown"

    fake.cases.append({**deepcopy(alert_case), "id": "case-duplicate"})
    with pytest.raises(reconcile.ReconcileError, match="multiple cases"):
        reconcile.reconcile_alert_case(fake, "workspace-1", source, repair=True)


def test_table_drift_rebuilds_only_managed_table(
    fake: FakeTracecat, source: dict[str, Any]
) -> None:
    alert_case = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    first = reconcile.reconcile_validation_table(
        fake, "workspace-1", alert_case["id"], source, repair=True
    )
    fake.tables.append(
        {"id": "unrelated", "name": "other", "columns": [], "rows": []}
    )
    fake.tables[0]["rows"][3]["weight"] = 999
    rebuilt = reconcile.reconcile_validation_table(
        fake, "workspace-1", alert_case["id"], source, repair=True
    )
    assert rebuilt["id"] != first["id"]
    assert any(table["id"] == "unrelated" for table in fake.tables)
    assert fake.tables[-1]["rows"] == [
        {"id": f"row-{index}", **row}
        for index, row in enumerate(source["validation_gates"], start=18)
    ]


def test_validation_gate_links_are_detected_and_removed(
    fake: FakeTracecat, source: dict[str, Any]
) -> None:
    alert_case = reconcile.reconcile_alert_case(
        fake, "workspace-1", source, repair=True
    )
    table = reconcile.reconcile_validation_table(
        fake, "workspace-1", alert_case["id"], source, repair=True
    )
    fake.links.append(
        {"row_id": "row-1", "table_id": table["id"], "case_id": alert_case["id"]}
    )
    with pytest.raises(reconcile.ReconcileError, match="linked"):
        reconcile.reconcile_validation_table(
            fake, "workspace-1", alert_case["id"], source, repair=False
        )
    reconcile.reconcile_validation_table(
        fake, "workspace-1", alert_case["id"], source, repair=True
    )
    assert fake.links == []
