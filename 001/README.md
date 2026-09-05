# Gym 001 — The Bigger Interview

An isolated, image-based Tracecat and Splunk Enterprise environment for the
[The Bigger Interview dataset](https://github.com/Kerberosse/soc-dataset-thebiggerinterview).
Tracecat is the pinned upstream production Compose stack; a Compose override
adds Gym 001 without modifying that snapshot.

## Start or migrate

Install the one-time host prerequisites:

```bash
brew install git-lfs just
git lfs install
git submodule update --init --recursive
```

An existing pre-001 stack must be migrated once so its OpenAI credential,
sessions, users, indexed events, and all other service state survive:

```bash
cd /Users/chris/repos/gyms/001
just migrate
```

For a fresh checkout:

```bash
SPLUNK_ACCEPT_TERMS=yes just up
just info
just status
just wait
```

`just down` keeps all volumes. Only `just reset CONFIRM=artifacts-captured` removes the new
Gym 001 volumes; it never removes legacy rollback volumes. The generated `.env`
is mode `0600`, is ignored by Git, and is never replaced silently.

## Evaluation

```bash
just eval
just eval RUNS=2
```

The default executes one independent, case-scoped investigation; `RUNS`
explicitly requests additional independent runs. Investigator sessions are
retained, and gitignored reports are stored in `eval-results/`. Reconciliation
creates the published alert as a native Tracecat case and the published
scorecard as a separate, unlinked `validation_gates` table. Only the tool-free
grader reads that table; the investigator receives the case and the Splunk MCP
integration. Before each evaluation, the harness verifies that integration's
pinned internal URI, HTTP/auth types, live connection, exact locked tool set,
and approval-free read policy. The source declaration is a Tracecat-maintained
transcription of the benchmark authors' public article—not an evaluator
distributed by the dataset repository. Each completed investigation report is
also appended to the alert case as a native comment. See
[`benchmark/README.md`](./benchmark/README.md) and [`PROVENANCE.md`](./PROVENANCE.md).

After preserving any useful session links and files, `just reset-evals
CONFIRM=artifacts-captured` replaces only the managed alert case and its
case-scoped chats, and removes any gym-titled grader session left by interrupted
cleanup. It retains the validation table, Splunk data, integration, presets,
credentials, and `eval-results/`.

## Restart or rebuild

`just restart` restarts Gym 001 while preserving its volumes, credentials,
cases, tables, and evaluation results. For a clean environment:

```bash
just clean-restart CONFIRM=artifacts-captured
```

The clean restart recreates only Gym 001 service volumes and then performs the
normal seed and reconciliation flow. Gitignored `eval-results/` remains on the
host. It does not act on any other gym directory.

## Images and auditing

`just up` calculates deterministic input hashes and selectively builds:

- `tracecat-gyms/gym-001-splunk:<input-hash>` (amd64, including compressed telemetry and MCP app)
- `tracecat-gyms/gym-001-control:<input-hash>` (native architecture, including `gymctl`, presets, and benchmark)

The only host bind mounts in the merged application are the rotating Splunk
license and evaluation result directory. Shared Tracecat source and image pins
live in `../platform.lock.json`; gym-specific artifacts, expected counts, and
the Splunk pin live in [`gym.lock.json`](./gym.lock.json).

Run `just check` for repository integrity and read-only validation against the
already-running stack. It never starts or resets services. `just
check-upstreams` performs the fail-closed online release and registry check.

The Splunk license expires at **2026-11-10T07:59:59Z**. Rotate it with:

```bash
just rotate-license FILE=/absolute/path/to/Splunk.License
```
