"""Deliberately update the pinned dataset submodule and its locked counts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.parse
import urllib.request

from . import config


REPOSITORY = "Kerberosse/soc-dataset-thebiggerinterview"


def _json(url: str):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tracecat-gyms/001"}), timeout=30) as response:
        return json.load(response)


def _counts(readme: str) -> tuple[dict[str, int], int]:
    counts = {name: int(value.replace(",", "")) for name, value in re.findall(r"\| `([^`]+)` \| ([0-9,]+) \|", readme)}
    total = re.search(r"\| \*\*total\*\* \| \*\*([0-9,]+)\*\* \|", readme)
    if len(counts) != 4 or not total:
        raise RuntimeError("could not derive expected counts from the upstream README")
    value = int(total.group(1).replace(",", ""))
    if sum(counts.values()) != value:
        raise RuntimeError("upstream count total is inconsistent")
    return counts, value


def update_dataset(reference: str) -> None:
    payload = _json(f"https://api.github.com/repos/{REPOSITORY}/commits/{urllib.parse.quote(reference, safe='')}")
    commit = str(payload["sha"])
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("GitHub returned an invalid dataset commit")
    path = config.ROOT / "upstream/dataset"
    subprocess.run(["git", "-C", str(path), "fetch", "--depth", "1", "origin", commit], check=True)
    subprocess.run(["git", "-C", str(path), "checkout", "--detach", commit], check=True)
    counts, total = _counts((path / "README.md").read_text())
    archive_url = f"https://github.com/{REPOSITORY}/archive/{commit}.tar.gz"
    with urllib.request.urlopen(urllib.request.Request(archive_url, headers={"User-Agent": "tracecat-gyms/001"}), timeout=60) as response:
        archive_sha = hashlib.sha256(response.read()).hexdigest()
    lock = config.load_lock()
    lock["sources"]["dataset"].update({"commit": commit, "archive_sha256": archive_sha})
    lock["expectations"]["events"] = {"sourcetypes": counts, "total": total}
    config.LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"Dataset submodule updated to {commit}; review the Git diff and rebuild the Splunk image.")
