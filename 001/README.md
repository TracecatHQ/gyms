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

`just down` keeps all volumes. Only `just reset CONFIRM=001` removes the new
Gym 001 volumes; it never removes legacy rollback volumes. The generated `.env`
is mode `0600`, is ignored by Git, and is never replaced silently.

## Evaluation

```bash
just eval
just eval RUNS=1
```

The default run executes three serial investigations, retains those Tracecat
sessions, and stores gitignored reports in `eval-results/`. The scorecard is a
Tracecat-maintained transcription of the benchmark authors' public article—not
an evaluator distributed by the dataset repository. See
[`benchmark/README.md`](./benchmark/README.md) and [`PROVENANCE.md`](./PROVENANCE.md).

## Images and auditing

`just up` calculates deterministic input hashes and selectively builds:

- `tracecat-gyms/gym-001-splunk:<input-hash>` (amd64, including compressed telemetry and MCP app)
- `tracecat-gyms/gym-001-control:<input-hash>` (native architecture, including `gymctl`, presets, and benchmark)

The only host bind mounts in the merged application are the rotating Splunk
license and evaluation result directory. All upstream versions, image-index
digests, artifact checksums, expected counts, and expected MCP tools live in
[`gym.lock.json`](./gym.lock.json).

Run `just check` for offline structural/unit validation and `just
check-upstreams` for the fail-closed online freshness and registry check.

The Splunk license expires at **2026-11-10T07:59:59Z**. Rotate it with:

```bash
just rotate-license FILE=/absolute/path/to/Splunk.License
```
