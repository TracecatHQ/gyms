from __future__ import annotations

from pathlib import Path

import pytest

from gymctl import config, host
from gymctl.cli import parser


def test_image_input_hashes_match_consolidated_lock() -> None:
    lock = config.load_lock()
    for component in ("splunk", "control"):
        assert config.image_input_hash(component) == lock["images"]["local"][component]["input_sha256"]
        assert config.local_image(component).endswith(config.image_input_hash(component)[:16])


def test_all_migration_volumes_have_stable_001_names() -> None:
    assert len(config.VOLUME_SUFFIXES) == 7
    assert {config.volume_name(config.PROJECT, suffix) for suffix in config.VOLUME_SUFFIXES} == {
        "tracecat-gym-001_core-db",
        "tracecat-gym-001_temporal-db",
        "tracecat-gym-001_minio-data",
        "tracecat-gym-001_redis-data",
        "tracecat-gym-001_sandbox-cache",
        "tracecat-gym-001_splunk-etc",
        "tracecat-gym-001_splunk-var",
    }


def test_normalized_volume_digest_detects_content_changes(tmp_path: Path) -> None:
    first = tmp_path / "one"
    first.write_text("one")
    before = host.volume_digest(tmp_path)
    first.write_text("two")
    assert host.volume_digest(tmp_path) != before


def test_public_cli_commands_parse() -> None:
    commands = ("build", "migrate", "up", "info", "status", "wait", "reconcile", "eval", "logs", "down", "clean-restart", "reset", "rotate-license", "update-upstreams", "update-dataset", "check")
    command_parser = parser()
    examples = {
        "clean-restart": ["clean-restart", "--confirm", "001"],
        "reset": ["reset", "--confirm", "001"],
        "rotate-license": ["rotate-license", "--file", "/tmp/license"],
        "update-dataset": ["update-dataset", "--ref", "main"],
    }
    for command in commands:
        assert command_parser.parse_args(examples.get(command, [command])).command == command


def test_clean_restart_allows_fresh_state_with_legacy(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(host, "reset", lambda confirm: calls.append(("reset", confirm)))
    monkeypatch.setattr(
        host,
        "up",
        lambda *, allow_fresh_with_legacy=False: calls.append(
            ("up", allow_fresh_with_legacy)
        ),
    )

    host.clean_restart("001")

    assert calls == [("reset", "001"), ("up", True)]


def test_clean_restart_requires_exact_confirmation(monkeypatch) -> None:
    called = False

    def unexpected_up(*, allow_fresh_with_legacy=False) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(host, "up", unexpected_up)

    with pytest.raises(host.GymError, match="reset destroys Gym 001 state"):
        host.clean_restart(None)

    assert called is False
