# Contributing a gym

Every gym uses the shared Tracecat evaluation loop. A gym contributes Case
Templates, a Rubric, two agent presets, and only the target-specific services or
Judge helpers it needs. Do not add a gym CLI, provisioning plugin, copied
Tracecat checkout, or Python control runtime.

## Naming

| Item | Convention |
|---|---|
| Gym directory | Next zero-padded number: `NNN/` |
| Candidate preset | Name `Candidate`, slug `candidate` |
| Judge preset | Name `Judge`, slug `judge` |
| Standard workflows | `Candidate Run` / `candidate_run` and `Judge Run` / `judge_run` |
| Helper workflow file | Kebab case, such as `validate-firewall-rule.yml` |
| Helper workflow alias | Snake case, such as `validate_firewall_rule` |
| Case Template ID | Stable kebab case |
| Rubric and criterion IDs | Stable kebab case |

The Case is the Candidate's unit of work. Candidate-visible analysis, evidence,
timelines, and answers belong in the Case description or comments. The Oracle
contains hidden expected facts. The Rubric describes how the visible Work
Product is graded. There is no separate “COT” object.

## Required layout

```text
NNN/
├── README.md
├── compose.yml                 # target services only
├── evals/
│   ├── cases.ndjson            # one Case Template per line
│   └── rubric.json             # one versioned scoring contract
├── assets/                     # source data, optional
├── target/                     # target configuration, optional
├── tracecat/
│   ├── tracecat.json           # workspace manifest
│   ├── agent_presets/
│   │   ├── candidate.md
│   │   └── judge.md
│   └── workflows/              # Judge helpers only, optional
└── terraform/main.tf           # shared module invocation
```

Use only `README.md` for gym documentation. Put source attribution next to the
asset it describes or in the README; do not add `IMPLEMENTATION.md` or a
gym-level `PROVENANCE.md`.

## Create a gym

1. Choose the next `NNN` directory and copy
   [`templates/gym-readme.md`](templates/gym-readme.md) to `NNN/README.md`.
2. Add Case Templates and the Rubric under `NNN/evals/`.
3. Add Candidate and Judge instructions under `NNN/tracecat/agent_presets/`.
4. Add the minimal `tracecat.json` manifest. Omit empty optional sections.
5. Add only the target services to `compose.yml`. Add a Judge helper workflow
   only when deterministic scoring needs to exercise the target.
6. Copy the closest existing `terraform/main.tf`, change `gym_id`, and retain
   only the credential variables the gym uses.
7. Add target variables to the root `.env.example`; do not create a per-gym
   environment file.
8. Add the gym to the root README table and run `just check`.

The root Justfile discovers directories matching `NNN/` automatically. Adding a
gym must not require another CLI command or a gym-specific Just recipe.

## Case Template contract

`evals/cases.ndjson` contains one complete evaluation unit per line:

```json
{"schema_version":1,"case_id":"stable-case-id","case":{"title":"Candidate-visible title","description":"Candidate-visible question","priority":"medium","severity":"medium","tags":[],"fields":{},"dropdowns":{},"payload":{}},"oracle":{"criteria":{"criterion-id":{"expected":"hidden expected result"}}}}
```

Keep each gym to at most 200 Case Templates, Tracecat's maximum table page size.
Split a larger suite into multiple gyms instead of adding pagination machinery
to the standard Candidate Run.

Terraform stores the Case Template, Oracle, and Rubric in the Tracecat
`case_templates` table. Candidate Run creates the Trial Case from `case` only;
the Candidate preset has no table access. After the submission cutoff, Judge
Run combines the frozen Submission with `oracle` and the Rubric. Every Oracle
criterion key must match one Rubric criterion ID. Keep executable verifier
fixtures in the helper workflow and only their expected outcomes in the Oracle.
Candidate Run may also attach
platform-captured call and result events to the Trial as `tool_audit`. Events
are joined by `tool_call_id`; call events contain tool names and inputs, while
result events record success. This is verifier metadata, not private model
reasoning.

## Rubric contract

`evals/rubric.json` is the single scoring contract for every Case Template in a
gym:

```json
{
  "schema_version": 1,
  "rubric_id": "gym-NNN-purpose",
  "rubric_version": 1,
  "criteria": [
    {
      "criterion_id": "criterion-id",
      "label": "Human-readable criterion",
      "weight": 100,
      "hard_gate": false,
      "judge_instruction": "What evidence makes this met or missed."
    }
  ]
}
```

Non-gate weights must total 100. Hard gates have weight 0 and force the Trial
score to 0 when missed. The Judge returns every criterion exactly once as
`met` or `missed`, with a reason and evidence references.

## Tracecat manifest contract

The shared module creates the workspace tables and the two standard workflows.
The gym manifest declares the two presets and only its optional integrations,
secrets, and helper workflows:

```json
{
  "schema_version": 1,
  "workspace_name": "Gym NNN — Title",
  "agent_presets": [
    {
      "name": "Candidate",
      "slug": "candidate",
      "description": "Candidate task.",
      "instructions_file": "agent_presets/candidate.md",
      "actions": ["core.cases.get_case", "core.cases.update_case"]
    },
    {
      "name": "Judge",
      "slug": "judge",
      "description": "Grades the captured Work Product.",
      "instructions_file": "agent_presets/judge.md",
      "actions": [],
      "retries": 1
    }
  ]
}
```

Candidate presets must not have table access. Judge presets receive hidden
material through Judge Run; grant them only the helper action they require.

Optional credential mappings keep the generic `just plan` and `just apply`
wrappers free of gym-specific branches. Map Tracecat field names to root `.env`
variable names in the object that consumes them:

```json
{
  "mcp_integrations": [{
    "catalog_slug": "example-mcp",
    "credentials_from_env": {"Authorization": "EXAMPLE_MCP_AUTHORIZATION"}
  }],
  "secrets": [{
    "name": "gym_NNN_target",
    "keys_from_env": {"API_TOKEN": "GYM_NNN_API_TOKEN"}
  }]
}
```

Terraform receives these values through ephemeral, sensitive variables; the
manifest stores only environment variable names.

Managed workflow YAML is source-owned: edit it locally and apply Terraform.
Do not commit workflow changes from the Tracecat canvas; the API normalizes
committed definitions, so this minimal provider intentionally does not compare
exported canvas state with source YAML.

## Results contract

The shared module writes `case_templates`, durable `evaluation_runs`, and
`evaluation_scores`. The Candidate Run execution ID is the Evaluation Run ID;
Candidate Run persists its immutable Trial snapshot in `evaluation_runs`, and
Judge Run reads that native Tracecat table. `just export NNN RUN_ID=...` writes
this fixed CSV schema:

```text
schema_version,gym_id,evaluation_run_id,trial_id,case_id,trial_number,candidate_session_id,judge_run_execution_id,judge_session_id,rubric_id,rubric_version,criterion_id,criterion_weight,criterion_result,criterion_points,criterion_hard_gate,trial_hard_failed,trial_score,reason,evidence_refs,candidate_completed_at,judged_at
```

Do not add gym-specific score columns. Put gym-specific detail in criterion IDs,
reasons, and evidence references.

## README contract

Every gym README follows [`templates/gym-readme.md`](templates/gym-readme.md)
with exactly these sections:

1. Task
2. Scoring
3. Target
4. Agent access
5. Run

Keep implementation details in configuration files. The README should explain
the evaluation contract, prerequisites, access boundaries, and commands.

## Validate and run

```bash
just check
just tracecat-up
just init NNN
just up NNN
just plan NNN
just apply NNN
just run NNN
just status NNN RUN_ID=<candidate-run-id>
just judge NNN RUN_ID=<candidate-run-id>
just status NNN RUN_ID=<judge-run-id>
just export NNN RUN_ID=<candidate-run-id>
```

A gym is ready when Terraform can plan it, Candidate Run creates fresh Trial
Cases and returns immutable Trials, Judge Run scores every Trial, the CSV
exports with the shared schema, and `just check` passes. Repeated measurements
are separate Candidate Runs, not repetitions inside one run.
