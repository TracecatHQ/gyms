# Gym 003 — Vulnerability Firewall Mitigation

Turn one n8n vulnerability report into a deployable ModSecurity ruleset.

## Task

The Candidate writes exactly one clearly designated ruleset plus its rationale
on the Trial Case. Judge Run extracts that ruleset and invokes the Judge-only
`Validate Firewall Rule` workflow against the live target.

## Scoring

- Deployable, activatable, healthy, and cleaned-up ruleset: hard gate
- Five malicious request variants blocked: 10 points each
- Five benign request variants preserved: 10 points each

A Candidate-caused syntax, activation, or outage failure misses the hard gate.
A target or helper failure fails the evaluation instead of creating a score.

## Target

Gym 003 starts pinned n8n and BunkerWeb services. The helper workflow owns the
executable malicious and benign fixtures; `evals/cases.ndjson` stores only their
expected outcomes. Set `N8N_ENCRYPTION_KEY`, `BUNKERWEB_DB_PASSWORD`, and
`BUNKERWEB_API_TOKEN` in the root `.env`.

## Agent access

The Candidate has Case actions only. The Judge receives the captured Submission
and may invoke the validation helper exactly once. Only the helper receives the
BunkerWeb secret and target-network access.

## Run

Run from the repository root:

```bash
just tracecat-up
just init 003
just up 003
just plan 003
just apply 003
just run 003
just status 003 RUN_ID=<evaluation-run-id>
just judge 003 RUN_ID=<evaluation-run-id>
just export 003 RUN_ID=<evaluation-run-id>
```
