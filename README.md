# Tracecat RL gyms

Self-contained, reproducible environments for evaluating security agents. Gym
directories use stable numeric identifiers so upstream scenario titles can
change without breaking automation or persisted Docker state.

| Gym | Scenario | Upstream | Services | Data license |
|---|---|---|---|---|
| [`001`](./001/) | The Bigger Interview | [Kerberosse/soc-dataset-thebiggerinterview](https://github.com/Kerberosse/soc-dataset-thebiggerinterview) | Tracecat, Splunk Enterprise, Splunk MCP Server | CC BY-NC-SA 4.0 |
| [`002`](./002/) | BOTSv3 analyst | Splunk Boss of the SOC v3 | Tracecat, MinIO, DuckDB | Upstream dataset terms |
| [`003`](./003/) | Vulnerability-driven firewall mitigation | n8n 1.65.0 / CVE-2026-21858 | Tracecat, n8n, Nuclei, BunkerWeb, MinIO | Mixed; see provenance |

Each gym documents which files are verbatim upstream material, derived benchmark
material, locally authored control code, and user-supplied artifacts.

## Repository layout

- `src/gymctl/` is the shared command runtime. Each numbered gym supplies a thin
  `src/gym_plugin/` implementation and keeps its own `Justfile` command surface.
- `upstream/tracecat/`, `compose/tracecat.override.yml`,
  `config/tracecat.env.example`, and `platform.lock.json` define the single
  pinned Tracecat platform shared by every gym.
- `<gym>/benchmark/agent/` contains investigator prompts, presets, and skills.
  `<gym>/benchmark/evals/` contains grader-only contracts and truth labels.
- `<gym>/images/control/` is the deterministic control image containing the
  shared runtime plus that gym's plugin and benchmark. Other image directories,
  such as `001/images/splunk/`, exist only when a gym needs another built image.

Unit-test suites are intentionally not shipped with the gyms. `just check`
validates repository integrity and the already-running gym stack without
starting or destroying it.

`just update-upstreams` may be run from either gym and updates the shared
Tracecat snapshot, platform lock, common OCI pins, gym-specific OCI pins, and
derived local-image hashes for the entire repository; the resulting cross-gym
diff must be reviewed together.
