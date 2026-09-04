from __future__ import annotations

from pathlib import Path

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
    commands = ("build", "migrate", "up", "info", "status", "wait", "reconcile", "eval", "logs", "down", "reset", "rotate-license", "update-upstreams", "update-dataset", "check")
    command_parser = parser()
    examples = {
        "reset": ["reset", "--confirm", "001"],
        "rotate-license": ["rotate-license", "--file", "/tmp/license"],
        "update-dataset": ["update-dataset", "--ref", "main"],
    }
    for command in commands:
        assert command_parser.parse_args(examples.get(command, [command])).command == command
