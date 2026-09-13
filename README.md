# Tracecat gyms

Security-agent evaluations provisioned as Tracecat configuration. Terraform owns
the platform resources; Docker Compose owns only the scenario targets; `just`
contains thin lifecycle and REST-trigger wrappers. There is no gym CLI, Python
control runtime, copied Tracecat source tree, or per-gym provisioning plugin.

## Standard vocabulary

| Name | Meaning | Stable local representation |
|---|---|---|
| Case Template | One evaluation question plus hidden answer material | One line in `evals/cases.ndjson`; one row in `case_templates` |
| Case | Fresh Tracecat Case created for one attempt | Candidate-visible question and Work Product |
| Trial | One Candidate attempt on one Case Template | Runtime Case UUID |
| Evaluation Run | Selected templates × repetitions | One row in `evaluation_runs` |
| Candidate | Agent under test | Agent preset slug `candidate` |
| Judge | Verifier agent | Agent preset slug `judge` |
| Candidate Run | Batch workflow that creates Trials and runs the Candidate | Workflow alias `candidate_run` |
| Judge Run | Batch workflow that grades completed Trials | Workflow alias `judge_run` |
| Oracle | Hidden expected facts or fixture outcomes | `oracle` in NDJSON and `case_templates` |
| Rubric | Versioned list of scoring criteria | `evals/rubric.json` and `case_templates` |
| Work Product | Candidate-authored Case state and comments | Tracecat Case |
| Submission | Immutable Case-and-comments snapshot at Candidate completion | JSON plus SHA-256 recorded on the Trial |
| Criterion Result | `met` or `missed`, with a reason and evidence references | One row in `evaluation_scores` |

There is deliberately no “COT” object. Private model reasoning is not a graded
artifact. Visible analysis that matters must be written into the Case Work
Product; its evaluation contract is called the Rubric. Candidate presets have no
table access, so only the Judge path receives the Oracle and Rubric.

## One shape for every gym

```text
NNN/
├── README.md
├── compose.yml                 # target services only
├── evals/
│   ├── cases.ndjson            # canonical Case Templates
│   └── rubric.json             # canonical Rubric
├── target/                     # target configuration, if required
├── tracecat/
│   ├── tracecat.json           # workspace manifest
│   ├── agent_presets/
│   └── workflows/              # gym-only helper workflows
└── terraform/main.tf           # shared module invocation
```

The shared module in `terraform/modules/gym` always provisions exactly three
tables: `case_templates`, `evaluation_runs`, and `evaluation_scores`. It also
provisions the workspace, presets, native YAML workflows, model bindings,
Case metadata, MCP catalog integrations, and write-only secrets.

Tracecat itself is cloned at the exact public release in `TRACECAT_VERSION` into
ignored `.cache/tracecat`; it is never vendored here. The repository-local Go
provider in `terraform-provider-tracecat` talks only to Tracecat's public REST
API. Workspace destruction is protected by Terraform `prevent_destroy`.

## Commands

Copy `.env.example` to `.env`, replace every placeholder, and create an
organization service-account API key in Tracecat with workspace administration
scopes. On the pinned beta release, enable the `service_accounts` entitlement
for the local organization's tier first; `.env.example` enables the documented
`agent-presets` feature-to-entitlement migration for a fresh database. Configure
credentials in Tracecat for the model providers named in `.env`; model secrets
remain organization settings rather than gym state. Terraform 1.11+, Go,
Docker, `just`, `jq`, `curl`, Git LFS, and Ruby are required.

```bash
just tracecat-up
just init
just up 001
just plan 001
just apply 001
just run 001
just run 002 CASE_IDS=sigma-web-password-spray REPETITIONS=3
just judge 001 RUN_ID=<evaluation-run-id>
just status 001 RUN_ID=<evaluation-run-id>
just export 001 RUN_ID=<evaluation-run-id>
```

`Candidate Run` and `Judge Run` are asynchronous REST triggers. A Trial always
uses a fresh Case and fresh agent session. Judge Run accepts only a completed,
previously unjudged Evaluation Run, invokes a fresh Judge for every Trial, and
writes immutable criterion rows. Tracecat snapshots the current preset head onto
each agent session. Before triggering Judge Run, `just judge` verifies every
Candidate session against the recorded version UUID and refuses to grade if the
Judge head changed; do not run `terraform apply` concurrently with either run.
A missed hard gate forces `trial_score` to 0.

Exports are written to `NNN/results/<run-id>/scores.csv` with this fixed schema:

```text
schema_version,gym_id,evaluation_run_id,trial_id,case_id,trial_number,candidate_run_execution_id,candidate_preset_version_id,candidate_model,judge_run_execution_id,judge_preset_version_id,judge_model,rubric_id,rubric_version,criterion_id,criterion_weight,criterion_result,criterion_points,criterion_hard_gate,trial_hard_failed,trial_score,reason,evidence_refs,case_template_sha256,submission_sha256,candidate_completed_at,judged_at
```

`just check` validates all NDJSON/Rubric contracts, workflow YAML, Terraform
formatting, and the provider tests without changing external state.

## Gyms

| Gym | Candidate task | Score |
|---|---|---|
| [001](001/) | Investigate one EventBridge alert and write the evidence-backed incident timeline to the Case | True-positive hard gate plus 16 weighted findings |
| [002](002/) | Classify 20 BOTSv3 alerts from exact bounded evidence objects | Determination 50; incident relevance 50 |
| [003](003/) | Turn one vulnerability report into one deployable ModSecurity ruleset | Deployability hard gate; 5 malicious and 5 benign fixtures at 10 points each |
