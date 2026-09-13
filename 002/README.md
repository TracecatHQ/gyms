# Gym 002 — BOTSv3 alert classification

Each of 20 Case Templates is a sparse alert plus one exact, read-only BOTSv3
object URL. The Candidate uses bounded DuckDB queries against that object and
records two independent decisions on the Trial Case:

- `determination`: true positive or false positive — 50 points
- `incident_relevance`: related or unrelated to the main BOTSv3 intrusion — 50 points

The Oracle stores expected decisions and exact evidence anchors. The Judge
grades only those two outcomes and their Case-scoped support; formatting,
embeddings, entities, memory, and process traces are intentionally out of scope.

Files:

- `evals/cases.ndjson`: 20 canonical Case Templates and hidden Oracles
- `evals/rubric.json`: the two-criterion scoring contract
- `tracecat/`: Candidate/Judge presets and workspace manifest
- `assets/botsv3-20260904T130332Z-1-001.zip`: pinned source corpus
- `compose.yml`: MinIO evidence target and one-shot declarative seed

Run from the repository root:

```bash
just tracecat-up
just up 002
just init 002
just plan 002
just apply 002
just run 002
just judge 002 RUN_ID=<evaluation-run-id>
just export 002 RUN_ID=<evaluation-run-id>
```

The Candidate can use Case actions and DuckDB only. It cannot access evaluation
tables, workflows, arbitrary HTTP, or the internet. The Judge has no tools.
