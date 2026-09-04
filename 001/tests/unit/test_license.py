from __future__ import annotations

import time
from pathlib import Path

import pytest

from gymctl import license as license_metadata

ROOT = Path(__file__).parents[2]


def write_license(tmp_path: Path, expiration: int, license_type: str = "enterprise") -> Path:
    filename = tmp_path / "license.xml"
    filename.write_text(
        "<license><payload>"
        f"<type>{license_type}</type><group_id>Enterprise</group_id>"
        "<quota>10737418240</quota><creation_time>1</creation_time>"
        f"<expiration_time>{expiration}</expiration_time>"
        "</payload><signature>not-a-real-signature</signature></license>"
    )
    return filename


def test_reads_enterprise_metadata(tmp_path: Path) -> None:
    filename = write_license(tmp_path, int(time.time()) + 3600)
    metadata = license_metadata.load_metadata(filename)
    assert metadata["type"] == "enterprise"
    assert metadata["group_id"] == "Enterprise"
    assert metadata["quota_bytes_per_day"] == 10 * 1024 * 1024 * 1024


def test_expired_license_has_actionable_error(tmp_path: Path) -> None:
    filename = write_license(tmp_path, 1)
    metadata = license_metadata.load_metadata(filename)
    with pytest.raises(license_metadata.LicenseError, match="just rotate-license") as raised:
        license_metadata.validate_current(metadata)
    assert "1970-01-01T00:00:01Z" in str(raised.value)
    assert str(metadata["sha256"]) in str(raised.value)


def test_checksum_mismatch_fails_closed(tmp_path: Path) -> None:
    filename = write_license(tmp_path, int(time.time()) + 3600)
    metadata = license_metadata.load_metadata(filename)
    with pytest.raises(license_metadata.LicenseError, match="checksum mismatch"):
        license_metadata.validate_current(metadata, expected_sha="0" * 64)


def test_rejects_non_enterprise_license(tmp_path: Path) -> None:
    filename = write_license(tmp_path, int(time.time()) + 3600, "free")
    with pytest.raises(license_metadata.LicenseError, match="Enterprise"):
        license_metadata.load_metadata(filename)


def test_rejects_malformed_license(tmp_path: Path) -> None:
    filename = tmp_path / "malformed.License"
    filename.write_text("<license><payload>")
    with pytest.raises(license_metadata.LicenseError, match="valid XML"):
        license_metadata.load_metadata(filename)


def test_rejects_missing_license(tmp_path: Path) -> None:
    with pytest.raises(license_metadata.LicenseError, match="not found"):
        license_metadata.load_metadata(tmp_path / "missing.License")


def test_supplied_license_expiry_and_checksum_are_locked() -> None:
    filename = ROOT / "assets" / "Splunk.License"
    metadata = license_metadata.load_metadata(filename)
    assert metadata["expiration_time"] == 1794297599
    assert metadata["expiration_utc"] == "2026-11-10T07:59:59Z"
    assert (
        metadata["sha256"]
        == "41bbf6b6fe4325ff7b810de6e81912da21f90d4f79fa6a7410c1b3faaf966edb"
    )
