# Gym 002 benchmark boundary

`scenario.json` is the analyst-visible 20-case projection. Each payload carries
one explicit `event_object_key` and matching MinIO URL; neither is inferred from
an alert timestamp.

`agent/` contains the investigator preset, prompts, and seven skills. It cannot
search other cases. URLscan access is retrieval-only, and no tool may submit a
new scan.

`evals/cases.json` is grader-only. It contains the independent determination and
incident-relevance labels, the exact object key, audited anchor references, and
case-specific enrichment requirements. It contains no writeup answer bank,
passwords, or provider secrets. `evaluation.json` defines ordered gates and the
locked tool-free grader.

Object/tag/reference/enrichment gates are computed from the Tracecat session
and final case state. The exact-object gate rejects persistent tables, dynamic
or alternate paths, additional relations, I/O functions, and multiple or
mutating SQL statements. It walks DuckDB's parsed query tree, so an unused CTE
cannot make an unrelated result count as exact-object evidence. The grader
decides only whether the cited evidence supports both conclusions. One
evaluation is one case and passes only when all of its ordered binary gates are
`met`; there is no weighting or cross-case aggregate.
