from pathlib import Path

from gymctl.dataset import validate_archive


def test_canonical_archive_identity_and_members():
    state = validate_archive()
    assert len(state["members"]) == 71
    assert state["record_count"] == 489_968
    assert all(item.filename.startswith("botsv3/botsv3_2018-08-") for item in state["members"])
    assert all(item.filename.endswith(".jsonl.gz") for item in state["members"])


def test_dataset_is_not_in_control_image_context():
    root = Path(__file__).resolve().parents[1]
    assert "assets" not in (root / "images/control/Dockerfile").read_text()
    assert "assets/" in (root / ".dockerignore").read_text()
