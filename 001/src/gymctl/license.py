#!/usr/bin/env python3
"""Read only the non-secret metadata from a Splunk XML license."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


class LicenseError(ValueError):
    pass


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_text(root: ET.Element, name: str) -> str:
    for element in root.iter():
        if _local_name(element.tag) == name and element.text:
            return element.text.strip()
    raise LicenseError(f"license is missing <{name}>")


def load_metadata(license_file: Path) -> dict[str, object]:
    if not license_file.is_file():
        raise LicenseError(f"license file not found: {license_file}")
    raw = license_file.read_bytes()
    if len(raw) > 1024 * 1024:
        raise LicenseError("license file exceeds the 1 MiB safety limit")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise LicenseError(f"license is not valid XML: {exc}") from exc

    try:
        creation = int(_first_text(root, "creation_time"))
        expiration = int(_first_text(root, "expiration_time"))
        quota = int(_first_text(root, "quota"))
    except ValueError as exc:
        raise LicenseError("license timestamps and quota must be integers") from exc

    license_type = _first_text(root, "type")
    group_id = _first_text(root, "group_id")
    if license_type.lower() != "enterprise" or group_id.lower() != "enterprise":
        raise LicenseError(
            f"expected a Splunk Enterprise license, got type={license_type!r} group_id={group_id!r}"
        )
    if quota <= 0:
        raise LicenseError("license quota must be positive")

    return {
        "type": license_type,
        "group_id": group_id,
        "quota_bytes_per_day": quota,
        "creation_time": creation,
        "expiration_time": expiration,
        "expiration_utc": datetime.fromtimestamp(
            expiration, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def validate_current(
    metadata: dict[str, object], expected_sha: str | None = None
) -> None:
    actual_sha = str(metadata["sha256"])
    if expected_sha and actual_sha != expected_sha:
        raise LicenseError(
            f"license checksum mismatch: expected {expected_sha}, got {actual_sha}"
        )
    expiration = int(metadata["expiration_time"])
    if expiration <= int(time.time()):
        raise LicenseError(
            "Splunk Enterprise license expired at "
            f"{metadata['expiration_utc']} (SHA-256 {actual_sha}). "
            "Replace it with: just rotate-license FILE=/absolute/path/to/license"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("license_file", type=Path)
    parser.add_argument("--expected-sha")
    parser.add_argument("--require-valid", action="store_true")
    args = parser.parse_args()
    try:
        metadata = load_metadata(args.license_file)
        if args.require_valid:
            validate_current(metadata, args.expected_sha)
    except LicenseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
