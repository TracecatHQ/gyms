# Gym 003 provenance

## Runtime sources

The vulnerable service runs the official `n8nio/n8n:1.65.0` multi-architecture
image. The security scenario comes from n8n's official GHSA advisories, while
the runtime and workflow fixtures come from n8n's official image and source
repository. No third-party proof-of-concept code is included.
n8n webhook success/error execution payload persistence is disabled so reviewed file-read responses do not recursively inflate its SQLite database.

BunkerWeb `1.6.14`, its scheduler, and its API are official `bunkerity` images.
The implementation follows the versioned BunkerWeb API documentation and the
official custom configuration endpoints: `GET /configs`, `POST /configs`, and
`GET`, `PATCH`, or `DELETE /configs/{service}/{type}/{name}`.

- BunkerWeb API: <https://docs.bunkerweb.io/1.6.14/api/>
- BunkerWeb source tag: <https://github.com/bunkerity/bunkerweb/tree/v1.6.14>
- n8n source tag: <https://github.com/n8n-io/n8n/tree/n8n%401.65.0>
- n8n CVE-2026-21858 advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg>
- n8n CVE-2025-68613 advisory: <https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp>
- ProjectDiscovery Nuclei release: <https://github.com/projectdiscovery/nuclei/releases/tag/v3.4.10>

`gym.lock.json` records every image source reference, manifest-list digest,
official registry page, publication timestamp, cooldown completion timestamp,
and the verified Linux ARM64 platform. Caddy also records and uses the ARM64
child digest from its official manifest so Docker cannot select a cached AMD64
child. The Docker Hub metadata endpoints in the lock are read by
`tools/verify_supply_chain.py` without pulling images.

The Tracecat and Tracecat UI release images were published on 2026-09-03, after
the 2026-08-30 cooldown cutoff. Their exact ARM64 digests were already present
on this host before this implementation began. Host preflight rejects these
young images on a fresh host and permits them here only by exact local digest;
they must not be pulled until 2026-09-10T20:14:58Z.

## WAF feasibility gate

The gate ran on this ARM64 Docker host with fresh named volumes and the same
digest-pinned BunkerWeb, scheduler, API, and MariaDB images used by the gym:

```text
python3 003/tools/waf_gate.py
PASS create+activate: restore sentinel returned HTTP 418
PASS log: request returned HTTP 200 and audit event contained rule 1003001
PASS block activation: request returned HTTP 403 and audit event contained rule 1003002
PASS remove: API returned 404 and former block marker returned HTTP 200
PASS restore: snapshotted sentinel became active and returned HTTP 418
PASS cleanup: gate configuration removed; ingress returned HTTP 200
FEASIBILITY GATE PASSED
```

The gate exposed a packaging detail that matters for evidence integrity:
BunkerWeb normally links `error.log` and `modsec_audit.log` to process file
descriptors. A one-shot, networkless initializer based on the same pinned
official scheduler image replaces those links with files owned by BunkerWeb
before startup. Its stable image identity prevents control-image rebuilds from
replacing files that BunkerWeb has open. The collector then mounts that volume
read-only, correlates the managed rule ID and ModSecurity `unique_id` with the
serial audit log, and writes bounded normalized events to the persistent job
volume. Neither the collector nor the test API receives the Docker socket.

The service baseline disables BunkerWeb's default Bad Behavior and request-rate
plugins, and disables CRS, BunkerNet, lists, and update checks. This prevents a
transient client ban or generic managed rule from masking the scenario result;
only the explicit Gym 003 ModSecurity rule changes the exploit verdict. The allowed-method list is declared explicitly so reviewed probe cleanup and normal editor traffic reach n8n.

## Dependency and download policy

The control image adds no Python package installation. It inherits the pinned
Tracecat image and copies the Nuclei `v3.4.10` executable from the official,
digest-pinned ProjectDiscovery image in a multi-stage build. The repository's
validation rejects non-exact Python requirement entries. Runtime services do
not install community n8n nodes, CRS bundles, or BunkerWeb plugins, and update
and telemetry features are disabled.
