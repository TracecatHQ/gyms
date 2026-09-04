# Provenance

| Path | Classification | Notes |
|---|---|---|
| `../upstream/tracecat/docker-compose.yml`, `Caddyfile` | `upstream-verbatim` | Shared exact files from the Tracecat release in `../platform.lock.json`. |
| `upstream/dataset` | `upstream-verbatim` | Git submodule pinned to the locked dataset commit. |
| `benchmark/scenario.json` | `derived-from-public-article` | Exact alert strings, validation-gate labels, and weights transcribed from the authors' article; the minimal JSON shape is local. |
| `benchmark/agent/` | `gym-owned` | Tracecat investigator prompt, preset, and run prompt. |
| `benchmark/evals/` | `gym-owned` | Tracecat grader prompt, preset, and evaluation configuration. |
| `src/gym_plugin/`, `images/`, `compose.override.yml`, `Justfile` | `gym-owned` | Gym-specific packaging and lifecycle behavior. |
| `../src/gymctl/`, `../compose/tracecat.override.yml`, `../config/tracecat.env.example` | `gym-owned` | Shared runtime and Tracecat Compose/environment layer. |
| `assets/splunk-mcp-server_200.tgz` | `user-supplied` | Official Splunk MCP Server 2.0.0 archive; checksum locked. |
| `assets/Splunk.License` | `user-supplied` | Rotating Splunk Enterprise license; metadata and checksum locked. |

The dataset is CC BY-NC-SA 4.0 and is intended here for noncommercial use.
Splunk software, the MCP package, and the supplied license remain governed by
their respective Splunk terms. See `gym.lock.json` for immutable identifiers.
