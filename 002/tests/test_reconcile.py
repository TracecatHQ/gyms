from gymctl.reconcile import source_cases


def test_case_payloads_are_sparse_and_hide_outcomes():
    cases = source_cases()
    assert len(cases) == 34
    assert len({case["payload"]["alert_id"] for case in cases}) == 34
    for case in cases:
        payload = case["payload"]
        assert payload["gym_id"] == "002"
        assert payload["event_object_url"].startswith("http://minio:9000/botsv3/")
        assert payload["event_object_url"].endswith(".jsonl.gz")
        assert not ({"outcome", "breach_related", "expected_verdict", "evidence_filters", "notes"} & payload.keys())
