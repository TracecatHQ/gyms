# Tracecat gyms

Security-agent evaluations provisioned as Tracecat configuration. Terraform
owns Tracecat resources, Docker Compose owns only scenario targets, and `just`
provides thin lifecycle and REST wrappers. The repository has no gym CLI,
Python control runtime, or copied Tracecat source tree.

Each evaluation follows the same path:

```text
Case Template → Candidate Run → Trial Case + durable Evaluation Run → Judge Run → scores.csv
```

The Case is the Candidate's unit of work. Visible analysis, evidence, timelines,
and final answers belong on that Case. Hidden expected facts are the Oracle;
the versioned grading contract is the Rubric. Private model reasoning is not a
stored or graded artifact.

## Quick start

Requirements: Terraform 1.11+, Go, Docker, `just`, `jq`, `curl`, Git LFS, and
Ruby.

Copy `.env.example` to `.env`, replace the runtime and target placeholders, and
start Tracecat:

```bash
just tracecat-up
```

In Tracecat, configure the model providers named in `.env` and create an
organization service-account API key with workspace administration scopes. The
pinned beta requires the `service_accounts` entitlement. Put the key in `.env`,
then run:

```bash
just init 001
just up 001
just plan 001
just apply 001
just run 001
just status 001 RUN_ID=<candidate-run-id>
just judge 001 RUN_ID=<candidate-run-id>
just status 001 RUN_ID=<judge-run-id>
just export 001 RUN_ID=<candidate-run-id>
```

Both triggers return a native Tracecat workflow execution ID and run
asynchronously. Wait for Candidate Run to complete before starting Judge Run,
then wait for Judge Run before exporting. Completed Candidate Runs are retained
in the Tracecat `evaluation_runs` table for later judging. Results are written
to `NNN/results/<candidate-run-id>/scores.csv`.

## Gyms

| Gym | Candidate task | Score |
|---|---|---|
| [001](001/) | Investigate one EventBridge alert and write an evidence-backed incident timeline | True-positive hard gate plus 16 weighted findings |
| [002](002/) | Classify 20 BOTSv3 alerts from bounded evidence objects | Exact-evidence hard gate; determination 50; incident relevance 50 |
| [003](003/) | Turn a vulnerability report into a deployable ModSecurity ruleset | Deployability hard gate; five malicious and five benign fixtures |

## Adding a gym

See [CONTRIBUTING.md](CONTRIBUTING.md) for naming, required files, evaluation
contracts, the README template, and the validation checklist.
