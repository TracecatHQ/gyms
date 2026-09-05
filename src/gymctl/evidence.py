"""Stable references for immutable JSONL evidence objects."""

from __future__ import annotations

import hashlib


EVENT_REF_VERSION = "sha256-object-line-v1"


def event_ref(object_key: str, line_number: int, raw_line: bytes) -> str:
    """Return a stable, globally scoped reference for one source JSONL record."""

    if not object_key or line_number < 1:
        raise ValueError(
            "event references require an object key and positive line number"
        )
    line = raw_line.rstrip(b"\r\n")
    digest = hashlib.sha256()
    digest.update(EVENT_REF_VERSION.encode("ascii"))
    digest.update(b"\0")
    digest.update(object_key.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(line_number).encode("ascii"))
    digest.update(b"\0")
    digest.update(line)
    return digest.hexdigest()
