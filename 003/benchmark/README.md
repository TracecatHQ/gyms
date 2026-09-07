# Gym 003 benchmark boundary

`scenario.json` is agent-visible business and route context. It intentionally
contains no expected verdicts, rule identifiers, exploit payloads, or grader
truth. Deterministic expectations live only under `benchmark/evals/`.

The scanner establishes version-based suspicion. Only the reviewed fixed-target
verification job may establish file-read or command-execution impact. Every
verification starts without a prior cookie or credential and cleanup is part of
the verdict.
