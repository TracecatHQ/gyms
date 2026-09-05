# Provenance

| Path | Classification | Notes |
|---|---|---|
| `../upstream/tracecat/` | `upstream-verbatim` | Shared exact Tracecat Compose and Caddy files pinned in `../platform.lock.json`. |
| `assets/botsv3-20260904T130332Z-1-001.zip` | `user-supplied` | Immutable Git LFS dataset artifact locked in `gym.lock.json`. |
| `benchmark/evals/cases.source.json` | `audited-derived` | Named public fields, exact source-object predicates, two-axis truth, and exact enrichment targets audited directly against BOTSv3. |
| `benchmark/scenario.json` | `generated-analyst-visible` | Exact 20-case projection generated from the audited specification. |
| `benchmark/evals/cases.json` | `generated-grader-only` | Two-axis oracle, exact object identity, stable anchor references, and enrichment contracts; no answer-bank secrets. |
| `benchmark/agent/` | `ported-and-gym-owned` | Seven incident-response skills plus case-native prompts and preset. |
| `tools/update_dataset.py`, `tools/botsv3/` | `gym-owned` | Strict compiler and read-only corpus contract audit. |
| `src/gym_plugin/`, `images/`, `compose.override.yml`, `Justfile` | `gym-owned` | Gym-specific dataset, reconciliation, evaluation, and lifecycle hooks. |
| `../src/gymctl/`, `../compose/tracecat.override.yml`, `../config/tracecat.env.example` | `gym-owned-shared` | Shared definitions, Compose invocation, agent sessions, evidence references, and Tracecat platform layer. |

The port does not modify a remote Tracecat workspace, AWS account, or source
archive. Hidden truth never enters analyst-visible case payloads or investigator
sessions. URLscan and VirusTotal use operator-configured Tracecat credentials,
never repository secrets.
