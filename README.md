# Tracecat RL gyms

Self-contained, reproducible environments for evaluating security agents. Gym
directories use stable numeric identifiers so upstream scenario titles can
change without breaking automation or persisted Docker state.

| Gym | Scenario | Upstream | Services | Data license |
|---|---|---|---|---|
| [`002`](./002/) | BOTSv3 analyst | Splunk Boss of the SOC v3 | Tracecat, MinIO, DuckDB | Upstream dataset terms |

Each gym documents which files are verbatim upstream material, derived benchmark
material, locally authored control code, and user-supplied artifacts.
