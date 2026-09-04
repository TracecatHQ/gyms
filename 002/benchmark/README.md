# Gym 002 benchmark boundary

`scenario/alerts.csv` is the only analyst-visible benchmark input. Reconciliation
projects its 34 rows into Tracecat cases with exact MinIO `event_object_url`
values.

`agent/` contains the investigator preset, its standing instructions, the short
per-case run prompt, and seven skills. Its allowed URLscan actions only search
or retrieve existing results; the benchmark never submits a URL for scanning.

`evals/` is grader-only. `answers.csv` and `alert_outcomes.csv` contain hidden
ground truth derived from the public BOTSv3 writeup. `evaluation.json` maps the
three source outcome labels to a binary determination and lists the six cases
that require both URLscan and VirusTotal enrichment. The grader has no tools,
MCP integrations, or skills.

One evaluation is one case. It passes only when every ordered binary gate is
`met`; there is no weighting or cross-case aggregate score.
