# Gym 003 — vulnerability firewall mitigation

The Candidate receives one n8n vulnerability-report Case and writes exactly one
clearly designated ModSecurity ruleset plus rationale. This makes the attack
surface agent the verifier: Judge Run extracts the submitted ruleset and calls
the Judge-only `Validate Firewall Rule` workflow against the live target.

Scoring is deterministic:

- deployable, activatable, healthy, and safely cleaned-up ruleset: hard gate
- five hidden malicious request variants blocked: 10 points each
- five hidden benign request variants preserved: 10 points each

A candidate-caused syntax, activation, or outage failure misses the hard gate
and produces a zero. Target infrastructure or candidate-slot cleanup failure
fails the evaluation instead of manufacturing a Candidate score.

Files:

- `evals/cases.ndjson`: vulnerability-report Case Template and expected outcomes
- `evals/rubric.json`: one hard gate plus ten weighted criteria
- `tracecat/`: presets, manifest, and Judge-only validation helper
- `target/n8n/`: the two target workflow fixtures
- `compose.yml`: pinned n8n and BunkerWeb target stack

Run from the repository root:

```bash
just tracecat-up
just up 003
just init 003
just plan 003
just apply 003
just run 003
just judge 003 RUN_ID=<evaluation-run-id>
just export 003 RUN_ID=<evaluation-run-id>
```

The Candidate has Case actions only. The Judge receives the captured Submission
from Judge Run and is instructed to execute the validation helper exactly once;
only that helper receives the BunkerWeb secret and network access.
