"""Persist sanitized job artifacts to the gym's MinIO bucket."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _sanitize(value: Any) -> Any:
    secret_fragments = tuple(
        fragment
        for fragment in (
            os.environ.get("GYM_TEST_API_TOKEN", ""),
            os.environ.get("BUNKERWEB_API_TOKEN", ""),
            os.environ.get("MINIO_ROOT_PASSWORD", ""),
            os.environ.get("GYM_N8N_STAFF_PASSWORD", ""),
            os.environ.get("N8N_ENCRYPTION_KEY", ""),
        )
        if fragment
    )
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items() if str(k).lower() not in {"password", "token", "secret", "authorization", "cookie", "set-cookie"}}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, str):
        result = value
        for fragment in secret_fragments:
            result = result.replace(fragment, "[REDACTED]")
        return result
    return value


def upload_job(record: dict[str, Any], evidence_dir: Path) -> list[dict[str, str]]:
    """Upload one canonical summary and any files produced by reviewed runners."""
    import boto3

    bucket = os.environ.get("MINIO_GYM_BUCKET", "gym-003-evidence")
    endpoint = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=os.environ["MINIO_ROOT_USER"],
        aws_secret_access_key=os.environ["MINIO_ROOT_PASSWORD"],
        region_name="us-east-1",
    )
    try:
        client.head_bucket(Bucket=bucket)
    except Exception:
        client.create_bucket(Bucket=bucket)
    safe = _sanitize(record)
    summary = evidence_dir / "summary.json"
    summary.write_text(json.dumps(safe, sort_keys=True, indent=2) + "\n")
    uploaded: list[dict[str, str]] = []
    for path in sorted(item for item in evidence_dir.rglob("*") if item.is_file()):
        relative = path.relative_to(evidence_dir).as_posix()
        key = f"runs/{record['run_id']}/{relative}"
        client.upload_file(str(path), bucket, key)
        uploaded.append({"bucket": bucket, "key": key, "url": f"s3://{bucket}/{key}"})
    return uploaded
