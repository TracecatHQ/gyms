# Provenance

| Path | Classification | Notes |
|---|---|---|
| `../upstream/tracecat/` | `upstream-verbatim` | Shared exact Tracecat Compose and Caddy files pinned in `../platform.lock.json`. |
| `assets/botsv3-20260904T130332Z-1-001.zip` | `user-supplied` | Canonical Git LFS dataset artifact locked in `gym.lock.json`. |
| `benchmark/scenario/alerts.csv` | `ported-derived` | Analyst-visible 34-alert projection ported from `TracecatHQ/automations/labs/botsv3`. |
| `benchmark/agent/` | `ported-and-gym-owned` | Seven incident-response skills plus the case-native investigator prompt and preset. |
| `benchmark/evals/` | `ported-and-gym-owned` | Hidden public-writeup answers/outcomes and the new 34-case binary grader contract. |
| `tools/update_dataset.py` | `ported-derived` | Deterministic generator for the visible alert and hidden evaluation CSVs. |
| `src/gym_plugin/`, `images/`, `compose.override.yml`, `Justfile` | `gym-owned` | Gym-specific packaging and lifecycle behavior. |
| `../src/gymctl/`, `../compose/tracecat.override.yml`, `../config/tracecat.env.example` | `gym-owned` | Shared runtime and Tracecat Compose/environment layer. |

The port does not alter a live Tracecat Labs workspace or a remote AWS bucket.
Hidden outcomes never enter analyst-visible case payloads or investigator
sessions. URLscan and VirusTotal are live Tracecat integrations configured by
the operator and are never populated from repository secrets.
