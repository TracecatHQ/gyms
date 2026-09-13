# Gym 002 — BOTSv3 Alert Classification

Classify 20 BOTSv3 alerts using exact, bounded evidence objects.

## Task

Each Case Template contains a sparse alert and one read-only BOTSv3 object URL.
The Candidate queries that object with DuckDB and records two independent
decisions, with Case-scoped evidence:

- `determination`: true positive or false positive
- `incident_relevance`: related or unrelated to the main BOTSv3 intrusion

## Scoring

Determination is worth 50 points and incident relevance is worth 50 points.
Both criteria require Tracecat's captured tool audit to show that every DuckDB
query read only the Case's exact evidence object; missing or out-of-scope access
scores zero. Formatting, embeddings, entities, memory, and private reasoning
are not scored.

## Target

Gym 002 starts a MinIO evidence target and seeds it from the pinned archive in
`assets/`. Set `BOTSV3_ACCESS_KEY` and `BOTSV3_SECRET_KEY` in the root `.env`.

## Agent access

The Candidate has Case actions and read-only DuckDB queries. It cannot access
evaluation tables or workflows, call arbitrary HTTP endpoints, or use the
internet. The Judge has no tools.

## Run

Run from the repository root:

```bash
just tracecat-up
just init 002
just up 002
just plan 002
just apply 002
just run 002
just status 002 RUN_ID=<candidate-run-id>
just judge 002 RUN_ID=<candidate-run-id>
just status 002 RUN_ID=<judge-run-id>
just export 002 RUN_ID=<candidate-run-id>
```
