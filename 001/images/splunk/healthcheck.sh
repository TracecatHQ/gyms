#!/usr/bin/env bash

set -euo pipefail

/sbin/checkstate.sh

license_file='/run/gym-assets/Splunk.License'
lock_file='/opt/gym/gym.lock.json'
if [[ ! -r "${license_file}" ]]; then
  printf 'ERROR: mounted Splunk license is missing or unreadable\n' >&2
  exit 1
fi
if [[ ! -r "${lock_file}" ]]; then
  printf 'ERROR: baked Gym 001 lock is missing or unreadable\n' >&2
  exit 1
fi

expiration_tag="$(grep -Eo '<expiration_time>[0-9]+</expiration_time>' "${license_file}" | head -n 1 || true)"
expiration_epoch="${expiration_tag#<expiration_time>}"
expiration_epoch="${expiration_epoch%</expiration_time>}"
if [[ ! "${expiration_epoch}" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: mounted Splunk license has no numeric expiration_time\n' >&2
  exit 1
fi
if (( expiration_epoch <= $(date +%s) )); then
  printf 'ERROR: Splunk Enterprise license expired at epoch %s; run just rotate-license FILE=/absolute/path\n' "${expiration_epoch}" >&2
  exit 1
fi

rest_response="$(mktemp)"
trap 'rm -f "${rest_response}"' EXIT
if ! curl -fsS --max-time 8 \
  --user "admin:${SPLUNK_PASSWORD}" \
  'http://127.0.0.1:8089/services/licenser/licenses?output_mode=json&count=0' \
  > "${rest_response}"; then
  printf 'ERROR: could not verify the installed Splunk license through splunkd REST\n' >&2
  exit 1
fi

/opt/splunk/bin/python3 - "${rest_response}" "${lock_file}" "${license_file}" <<'PY'
import hashlib
import json
import sys
import time

response_file, lock_file, license_file = sys.argv[1:]
with open(response_file, encoding="utf-8") as source:
    response = json.load(source)
with open(lock_file, encoding="utf-8") as source:
    expected = json.load(source)["artifacts"]["splunk_license"]
with open(license_file, "rb") as source:
    license_sha = hashlib.sha256(source.read()).hexdigest()
if license_sha != expected["sha256"]:
    raise SystemExit(
        "ERROR: mounted Splunk license checksum does not match gym.lock.json; "
        f"expected {expected['sha256']}, got {license_sha}"
    )

observed = []
for entry in response.get("entry", []):
    content = entry.get("content", {})
    if str(content.get("group_id", "")).lower() != "enterprise" and str(
        content.get("type", "")
    ).lower() != "enterprise":
        continue
    try:
        observed.append(int(content["expiration_time"]))
    except (KeyError, TypeError, ValueError):
        continue

expected_expiration = int(expected["expiration_time"])
if expected_expiration not in observed:
    raise SystemExit(
        "ERROR: installed Splunk Enterprise license does not match the tracked license; "
        f"expected expiration {expected_expiration}, observed {observed}"
    )
if expected_expiration <= int(time.time()):
    raise SystemExit(
        "ERROR: installed Splunk Enterprise license is expired; "
        "run just rotate-license FILE=/absolute/path"
    )
PY
