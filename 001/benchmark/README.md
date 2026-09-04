# Gym 001 benchmark provenance

The benchmark authors publish the alert, true-positive hard gate, and sixteen
weighted findings in the [scenario article](https://unsecure.sh/blog/agentic-soc-scenario/#validation-gates).
Those exact strings and weights are authoritative.

They do **not** publish an evaluator, JSON scorecard, prompts, grader, or runner
in the [dataset repository](https://github.com/Kerberosse/soc-dataset-thebiggerinterview).
Accordingly:

- `scenario.json` is a minimal **derived/transcribed** source declaration. It
  contains only the exact published alert context and facts plus the 17 gate
  labels and integer weights. The article's displayed Total footer is derived
  and is not stored as a gate.
- Everything under `agent/` and `evals/` is **gym-owned** Tracecat material.
- Reconciliation models the alert as one Tracecat case and the rows as an
  independent `validation_gates` table. No table row is linked to the case.
- Investigations are case-scoped, use the SOC analyst preset, and have only the
  Splunk MCP integration. The validation gates are loaded at evaluation time
  and supplied only to a tool-free grader.
- The grader emits one ordered binary determination (`met` or `missed`) per
  gate. A missed disposition gate hard-fails to 0/100; otherwise the score is
  the sum of weights for met rows.

This distinction prevents the local machine-readable representation and runner
from being mistaken for an upstream official evaluator.
