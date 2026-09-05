# Gym 002 — BOTSv3 analyst

Gym 002 is a local Tracecat Tier-1 SOC benchmark built from Splunk Boss of the
SOC v3. It presents 20 hand-audited provider alerts as native cases. Every case
points to the one hourly MinIO object containing its decisive evidence.

The analyst makes two independent decisions:

- determination: `true_positive` or `false_positive`
- incident relevance: `related` or `unrelated`

## Start

Requirements are Docker with Compose 2.24.4+, Git LFS, `just`, and Python 3.11+.

```bash
cd /Users/chris/repos/gyms/002
git lfs install
just init
just up
just info
```

The Tracecat UI listens only on `http://127.0.0.1:28080`. If initial
reconciliation reports that no model is configured, configure a provider and
organization-default model in the UI, then run `just reconcile` and `just
wait`.

URLscan and VirusTotal remain benchmark requirements for five applicable cases.
Configure `URLSCAN_API_KEY` and `VIRUSTOTAL_API_KEY` directly in Tracecat when
available. Missing credentials do not block an investigation; their gates are
reported as missed.

## Evaluation

```bash
# All 20 cases, sequentially
just eval

# One case
just eval ALERT_ID=guardduty:c2-contact
```

Each selected case must be pristine. The investigator can access only that
case, its exact MinIO object, the seven local reasoning skills, case-update
actions, DuckDB, and read-only enrichments. Cross-case search is not enabled.

MinIO records contain a stored, deterministic `event_ref`. The investigator
must select it directly, cite an audited anchor reference in the case, record
both decision tags, and close the case. The harness checks those mechanical
requirements deterministically. DuckDB evidence counts only when every query is
a single read-only query whose DuckDB-parsed result lineage reaches only the
case's literal `read_json_auto` URL. Unused CTEs and secondary relations do not
qualify. A tool-free grader evaluates only whether the cited evidence supports
both conclusions. There is no aggregate score.

Case sessions and gitignored artifacts under `eval-results/` are retained. Once
useful artifacts are captured, reset only Gym 002's managed cases and sessions:

```bash
just reset-evals CONFIRM=artifacts-captured
```

The command is interruption-safe and idempotent. It removes any remaining
`gym_id=002` cases and any gym-titled grader sessions left by interrupted
cleanup, then recreates the exact 20-case queue. Models, integration credentials,
skills, presets, service volumes, and host artifacts are retained.

## Dataset and evidence boundary

The canonical Git LFS artifact is
`assets/botsv3-20260904T130332Z-1-001.zip`, locked by checksum. It contains 71
gzip JSONL members and 489,968 records. The ZIP enters only the `dataset-seed`
container through a read-only mount. Seeding adds a
`sha256-object-line-v1` reference to each immutable source record before upload;
the archive itself is never modified or copied into an image.

`benchmark/evals/cases.source.json` declares public alert fields, exact evidence objects
and predicates, and the two hidden truth axes. Regenerate the two committed
artifacts with:

```bash
just update-dataset
```

Generation fails unless every positive anchor resolves to exactly one source
row and every negative predicate resolves to none. `just check` reruns this
corpus audit in memory and byte-compares the generated files.

## Validation and cleanup

`just status` checks the exact live cases, skills, presets, and enrichment
credential status. `just check` additionally validates the archive, generated
contracts, Compose model, control image, seeded dataset, and live service
health. It does not destroy state.

```bash
just reset CONFIRM=artifacts-captured
just clean-restart CONFIRM=artifacts-captured
```

These full-cleanup commands remove only Gym 002 Compose state and never delete
host `eval-results/`. A clean restart also removes the Tracecat database, so UI
model and integration settings must be configured again.

See [`benchmark/README.md`](benchmark/README.md) and
[`PROVENANCE.md`](PROVENANCE.md) for source and evaluator boundaries.
