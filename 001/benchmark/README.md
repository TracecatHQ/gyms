# Gym 001 benchmark provenance

The benchmark authors publish the true-positive hard gate and sixteen weighted
findings in the [scenario article](https://unsecure.sh/blog/agentic-soc-scenario/).
Those labels and weights are authoritative in substance.

They do **not** publish an evaluator, JSON scorecard, prompts, grader, or runner
in the [dataset repository](https://github.com/Kerberosse/soc-dataset-thebiggerinterview).
Accordingly:

- `scorecard.json` is a **derived/transcribed** representation. Every row keeps
  the exact article label and weight next to a stable local ID and expanded
  description.
- Everything under `harness/` is **gym-owned** Tracecat material.
- The scorecard stays out of the investigator preset and is supplied only to a
  tool-free grader preset.

This distinction prevents a local machine-readable harness from being mistaken
for an upstream official evaluator.
