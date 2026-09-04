# Gym 002 — BOTSv3 analyst

Gym 002 is a local Tracecat Tier-1 SOC benchmark built from Splunk Boss of the
SOC v3. It presents 34 provider-style alerts as native cases. Each case points
to one exact hourly gzip JSONL object in the local MinIO service; the analyst
must query that object with DuckDB, update the case, and make a binary
`true_positive` or `false_positive` determination.

## Start

Requirements are Docker with Compose 2.24.4+, Git LFS, `just`, and Python 3.11+.

```bash
cd /Users/chris/repos/gyms/002
git lfs install
just init
just up
just info
```

The initial `just up` may stop at reconciliation until a model is configured;
the application remains available. The Tracecat UI listens only on
`http://127.0.0.1:28080`. Run `just info`, configure a model provider and
organization-default model in the UI, then run `just reconcile` and `just wait`.
Also configure `URLSCAN_API_KEY` and `VIRUSTOTAL_API_KEY` in Tracecat when they
are available. Their absence is reported as `pending`; it does not prevent
reconciliation or evaluation, but the applicable enrichment gates will be
missed.

`just down` retains volumes and credentials. `just restart` performs a normal
stop/start with the same state. No command removes evaluation state without the
exact confirmation token described below.

## Evaluation

```bash
# All 34 cases, sequentially
just eval

# One case
just eval ALERT_ID=guardduty:c2-contact
```

Each alert is an independent evaluation. Before any selected case runs, the
harness refuses cases with prior sessions, comments, tags, or unmanaged drift.
The investigator receives only its case, the seven published/local reasoning
skills, DuckDB, case actions, and read-only enrichment actions. It cannot see
the hidden outcomes or grader prompt.

The tool-free grader checks the correct binary determination, a successful
bounded DuckDB query against the case's exact object, an evidence-based case
update with an `event_ref`, and the explicitly applicable URLscan/VirusTotal
lookups. Results are reported per case; there is no aggregate score. Transient
network/provider failures may be attempted three times, but semantic failures
are never retried. The suite continues through all selected cases and exits
nonzero if any case fails.

Investigator case sessions and gitignored artifacts under `eval-results/` are
retained. After capturing anything useful, reset only the 34 managed cases and
their case-scoped sessions with:

```bash
just reset-evals CONFIRM=artifacts-captured
```

This preserves the provider setup, URLscan/VirusTotal secrets, integrations,
skills, presets, dataset, service volumes, and host `eval-results/` directory.

## Dataset and evidence boundary

The canonical Git LFS artifact is
`assets/botsv3-20260904T130332Z-1-001.zip`, locked by checksum. It contains 71
hourly gzip JSONL members and 489,968 records. The ZIP is not copied into an
image. Only `dataset-seed` receives a read-only bind mount and copies the
members into MinIO; anonymous access permits exact object reads but not listing
or writing.

Regenerate the three benchmark CSVs with `just update-dataset` and the optional
flags shown by `python3 tools/update_dataset.py --help`. Generated alerts go to
`benchmark/scenario/`; hidden answers and outcomes go to `benchmark/evals/`.

## Validation and destructive cleanup

`just status` verifies the exact 34-case identity, seven published skills,
investigator and tool-free grader presets, and enrichment-secret status.
`just check` additionally verifies the repository, archive, Compose model,
control-image hash, seed completion, and health of the already-running stack.
It does not start or destroy services.

Full cleanup is deliberately explicit:

```bash
just reset CONFIRM=artifacts-captured
just clean-restart CONFIRM=artifacts-captured
```

Both commands remove only Gym 002 Compose volumes. The host `eval-results/`
directory is never deleted. `clean-restart` then performs the normal bootstrap;
because provider configuration lives in the removed database, it must be
configured again in the UI.

See [`benchmark/README.md`](benchmark/README.md) and
[`PROVENANCE.md`](PROVENANCE.md) for the evaluator and source boundaries.
