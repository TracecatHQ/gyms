# Gym 001 — The Bigger Interview

Investigate one EventBridge `DeleteRule` alert against the `investigation`
Splunk index.

## Task

The Candidate records its disposition, summary, queries, evidence, UTC
timeline, IOCs, uncertainties, recommendations, and final answer on the Trial
Case. Markdown and Mermaid timelines are both accepted; formatting is not
scored separately.

## Scoring

The Rubric has a true-positive hard gate and 16 weighted attack-chain criteria
totaling 100. Judge Run grades only the Case Work Product captured at the
Candidate cutoff.

## Target

Gym 001 builds a Splunk target from `target/splunk/` and the pinned dataset in
`assets/dataset/`. Supply `assets/Splunk.License` and initialize submodules
before starting it.

After `just up 001`, create a least-privilege Splunk user restricted to the
`investigation` index, mint an encrypted token in the installed Splunk MCP
Server app, and set `SPLUNK_MCP_AUTHORIZATION=Bearer <token>` in the root
`.env`. Terraform sends the header through a write-only attribute, so it is not
stored in plan or state.

## Agent access

The Candidate has Case actions and the Splunk MCP integration. It has no table,
workflow, arbitrary HTTP, or internet access. The Judge has no tools and
receives hidden evaluation material only from Judge Run.

## Run

Run from the repository root:

```bash
git submodule update --init --recursive
just tracecat-up
just init 001
just up 001
# Configure the Splunk user and SPLUNK_MCP_AUTHORIZATION here.
just plan 001
just apply 001
just run 001
just status 001 RUN_ID=<evaluation-run-id>
just judge 001 RUN_ID=<evaluation-run-id>
just export 001 RUN_ID=<evaluation-run-id>
```
