#!/usr/bin/env bash
set -euo pipefail

/sbin/checkstate.sh

license_file=/run/gym-assets/Splunk.License
test -r "$license_file"

expiration_tag="$(grep -Eo '<expiration_time>[0-9]+</expiration_time>' "$license_file" | head -n 1)"
expiration_epoch="${expiration_tag#<expiration_time>}"
expiration_epoch="${expiration_epoch%</expiration_time>}"
[[ "$expiration_epoch" =~ ^[0-9]+$ ]]
(( expiration_epoch > $(date +%s) ))

curl -fsS --max-time 8 \
  --user "admin:${SPLUNK_PASSWORD}" \
  'http://127.0.0.1:8089/services/licenser/licenses?output_mode=json&count=0' \
  | grep -q 'Enterprise'
