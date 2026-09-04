# Provenance

| Path | Classification | Notes |
|---|---|---|
| `upstream/tracecat/docker-compose.yml`, `Caddyfile` | `upstream-verbatim` | Exact files from the locked Tracecat release. |
| `upstream/dataset` | `upstream-verbatim` | Git submodule pinned to the locked dataset commit. |
| `benchmark/scenario.json` | `derived-from-public-article` | Exact alert strings, validation-gate labels, and weights transcribed from the authors' article; the minimal JSON shape is local. |
| `benchmark/harness/` | `gym-owned` | Tracecat prompts, presets, and evaluation configuration. |
| `src/gymctl/`, `images/`, `compose.override.yml`, `Justfile` | `gym-owned` | Tracecat's packaging and control plane. |
| `assets/splunk-mcp-server_200.tgz` | `user-supplied` | Official Splunk MCP Server 2.0.0 archive; checksum locked. |
| `assets/Splunk.License` | `user-supplied` | Rotating Splunk Enterprise license; metadata and checksum locked. |

The dataset is CC BY-NC-SA 4.0 and is intended here for noncommercial use.
Splunk software, the MCP package, and the supplied license remain governed by
their respective Splunk terms. See `gym.lock.json` for immutable identifiers.
