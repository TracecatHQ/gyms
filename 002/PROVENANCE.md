# Provenance

- Lab behavior, seed CSVs, generator, evaluator contract, and skills were ported on 2026-09-04 from `TracecatHQ/automations` at `labs/botsv3`.
- `assets/botsv3-20260904T130332Z-1-001.zip` is the user-supplied canonical dataset artifact. It is tracked with Git LFS and locked in `gym.lock.json`.
- `upstream/tracecat/docker-compose.yml` and `Caddyfile` are verbatim from the Tracecat release pinned in `gym.lock.json`.
- `compose.override.yml`, `src/gymctl`, image metadata, and local runtime documentation are Gym 002-owned port code.

This port does not alter any live Tracecat Labs workspace or remote AWS bucket. It removes the runtime dependency on both.
