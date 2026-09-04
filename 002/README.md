# Gym 002 — BOTSv3 analyst

Gym 002 is the BOTSv3 Tier-1 SOC analyst lab, ported from the former `TracecatHQ/automations` lab. The analyst, 34-case queue, hidden outcomes, skills, and evaluator contracts are preserved. Only storage and runtime wiring changed: evidence is served by the local Tracecat Compose stack's MinIO service.

## Dataset boundary

The canonical artifact is `assets/botsv3-20260904T130332Z-1-001.zip`, stored as one Git LFS object with SHA-256 `6cb50794622525c1823ae27a8d40a718aaab62b2d665bbb06584ec5a2163d70f`. It contains 71 hourly `jsonl.gz` members and 489,968 records.

The ZIP is excluded from Docker build contexts. `dataset-seed` alone receives it at `/run/gym-data/botsv3.zip` through a read-only bind mount and streams each member to the `botsv3` bucket. Anonymous access grants only `GetObject`; the bucket cannot be listed or written without MinIO credentials.

## Lifecycle

Requirements: Docker with Compose 2.24.4+, Git LFS, `just`, and `uvx`.

```bash
cd 002
just init
just up
just status
just reconcile
just down
just reset CONFIRM=002
just check
```

The Tracecat UI is available only on `http://127.0.0.1:28080`. `just info` prints the generated local credentials. On first bootstrap, configure a provider and organization-default model in Tracecat, then run `just reconcile`. The encrypted provider configuration and managed analyst preset persist across ordinary `just down` / `just up` demo cycles. `just reset CONFIRM=002` deliberately removes that local state and requires the one-time provider setup again.

## Evidence queries

Each case carries an exact `event_object_url`, for example `http://minio:9000/botsv3/botsv3_2018-08-20_09.jsonl.gz`.

```sql
select try_cast(_time as timestamp) as event_time, _sourcetype, source, host
from read_json_auto(
  'http://minio:9000/botsv3/botsv3_2018-08-20_09.jsonl.gz',
  format = 'newline_delimited'
)
limit 20;
```

Use the exact case URL: listing is intentionally unavailable. Never paste full `_raw` records into a case.

## Seed and evaluation data

- `data/alerts.csv` is analyst-visible seed input.
- `data/answers.csv` and `data/alert_outcomes.csv` are hidden evaluator inputs and are never added to case payloads.
- `evals.json` preserves the original evaluation contract.
- `generate_tables.py` regenerates the CSVs from the canonical ZIP (or an explicitly supplied JSONL glob) without requiring persistent extracted data.

See `PROVENANCE.md`, `INSTRUCTIONS.md`, and `ANALYST_INSTRUCTIONS.md` for the port boundary and analyst contract.
