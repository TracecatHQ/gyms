"""Read-only BunkerWeb log collector for the two managed ModSecurity rules."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path


LOG_DIR = Path(os.environ.get("GYM_WAF_LOG_DIR", "/var/log/bunkerweb"))
EVENTS = Path(os.environ.get("GYM_WAF_EVENTS_FILE", "/var/lib/gym/jobs/waf-events.jsonl"))
MANAGED_RULE_IDS = {9300301, 9300302}
LINE = re.compile(
    r"^(?P<stamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*"
    r'\[id "(?P<rule_id>\d+)"\].*\[msg "(?P<message>[^"]*)"\].*'
    r'\[hostname "(?P<host>[^"]*)"\].*\[uri "(?P<uri>[^"]*)"\].*'
    r'\[unique_id "(?P<unique_id>[^"]+)"\]'
)


def _audit_has(unique_id: str) -> bool:
    path = LOG_DIR / "modsec_audit.log"
    for _ in range(20):
        try:
            if unique_id in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


def _event(line: str) -> dict[str, object] | None:
    match = LINE.search(line)
    if match is None:
        return None
    rule_id = int(match.group("rule_id"))
    if rule_id not in MANAGED_RULE_IDS:
        return None
    timestamp = datetime.strptime(match.group("stamp"), "%Y/%m/%d %H:%M:%S").replace(tzinfo=UTC)
    unique_id = match.group("unique_id")
    return {
        "timestamp": timestamp.isoformat(),
        "rule_id": rule_id,
        "mode": "LOG_ONLY" if rule_id == 9300301 else "BLOCK",
        "message": match.group("message"),
        "host": match.group("host"),
        "uri": match.group("uri"),
        "unique_id": unique_id,
        "audit_correlated": _audit_has(unique_id),
        "blocked": "Access denied with code 403" in line,
    }


def main() -> None:
    """Follow the error log without ever opening the mounted files for writing."""

    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    error_log = LOG_DIR / "error.log"
    while not error_log.is_file():
        time.sleep(0.25)
    with error_log.open("r", encoding="utf-8", errors="replace") as source:
        source.seek(0, os.SEEK_END)
        while True:
            line = source.readline()
            if not line:
                time.sleep(0.1)
                continue
            event = _event(line)
            if event is None:
                continue
            with EVENTS.open("a", encoding="utf-8") as sink:
                sink.write(json.dumps(event, sort_keys=True) + "\n")
                sink.flush()
