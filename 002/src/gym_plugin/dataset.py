"""Validate the canonical ZIP and stream its gzip members into MinIO."""

from __future__ import annotations
import gzip
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

from gymctl.evidence import EVENT_REF_VERSION, event_ref

from . import config

MEMBER_RE = re.compile(r"^botsv3/(botsv3_2018-08-(?:17|18|19|20|21)_\d{2}\.jsonl\.gz)$")


def archive_path() -> Path:
    default = config.ROOT / config.load_lock()["artifacts"]["botsv3"]["path"]
    return Path(os.environ.get("BOTSV3_ARCHIVE", default))


def validate_archive(path: Path | None = None, *, count_records: bool = False) -> dict:
    path = path or archive_path()
    expected = config.load_lock()["artifacts"]["botsv3"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected["sha256"] or path.stat().st_size != expected["archive_bytes"]:
        raise RuntimeError(f"BOTSv3 archive identity mismatch: {digest}")
    records = 0
    with zipfile.ZipFile(path) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        names = [item.filename for item in members]
        if len(members) != expected["member_count"] or any(
            not MEMBER_RE.fullmatch(name) for name in names
        ):
            raise RuntimeError("BOTSv3 archive member set is invalid")
        if (
            len(set(names)) != len(names)
            or sum(item.file_size for item in members) != expected["member_bytes"]
        ):
            raise RuntimeError("BOTSv3 archive member metadata is invalid")
        if count_records:
            for item in members:
                with (
                    archive.open(item) as compressed,
                    gzip.GzipFile(fileobj=compressed) as stream,
                ):
                    records += sum(1 for line in stream if line.strip())
            if records != expected["record_count"]:
                raise RuntimeError(f"BOTSv3 record count mismatch: {records}")
    return {
        "path": path,
        "members": members,
        "record_count": records or expected["record_count"],
    }


def seed() -> None:
    from minio import Minio

    state = validate_archive()
    bucket = os.environ.get("BOTSV3_BUCKET", "botsv3")
    client = Minio(
        os.environ.get("BOTSV3_ENDPOINT", "minio:9000"),
        access_key=os.environ["MINIO_ROOT_USER"],
        secret_key=os.environ["MINIO_ROOT_PASSWORD"],
        secure=False,
    )
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    expected_keys: set[str] = set()
    record_count = 0
    with zipfile.ZipFile(state["path"]) as archive:
        for item in state["members"]:
            key = Path(item.filename).name
            expected_keys.add(key)
            object_records = 0
            with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as stream:
                with (
                    archive.open(item) as compressed,
                    gzip.GzipFile(fileobj=compressed) as source,
                    gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as destination,
                ):
                    for line_number, raw_line in enumerate(source, start=1):
                        if not raw_line.strip():
                            continue
                        event = json.loads(raw_line)
                        if "event_ref" in event:
                            raise RuntimeError(
                                f"source archive unexpectedly contains event_ref in {key}:{line_number}"
                            )
                        event["event_ref"] = event_ref(key, line_number, raw_line)
                        destination.write(
                            json.dumps(
                                event, ensure_ascii=True, separators=(",", ":")
                            ).encode("utf-8")
                            + b"\n"
                        )
                        object_records += 1
                length = stream.tell()
                stream.seek(0)
                client.put_object(
                    bucket,
                    key,
                    stream,
                    length,
                    content_type="application/gzip",
                    metadata={"event-ref-version": EVENT_REF_VERSION},
                )
            record_count += object_records
    for obj in client.list_objects(bucket):
        if obj.object_name not in expected_keys:
            client.remove_object(bucket, obj.object_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    client.set_bucket_policy(bucket, json.dumps(policy))
    objects = list(client.list_objects(bucket))
    if {o.object_name for o in objects} != expected_keys:
        raise RuntimeError("MinIO object verification failed")
    if record_count != state["record_count"]:
        raise RuntimeError(
            f"seeded record count mismatch: {record_count} != {state['record_count']}"
        )
    print(
        f"[dataset-seed] READY: {len(objects)} objects, {record_count} records, "
        f"event_ref={EVENT_REF_VERSION}",
        flush=True,
    )


def main() -> int:
    seed()
    return 0
