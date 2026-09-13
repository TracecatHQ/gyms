# Gym 001 — The Bigger Interview

The Candidate investigates one EventBridge `DeleteRule` alert against the
`investigation` Splunk index. The complete visible answer—disposition, summary,
queries, evidence, UTC timeline, IOCs, uncertainties, and recommendations—lives
on the Trial Case. Markdown or Mermaid are both acceptable; timeline formatting
is not scored separately.

The hidden Rubric has a true-positive hard gate and 16 weighted attack-chain
criteria totaling 100. Judge Run grades only the Case Work Product captured at
the Candidate cutoff.

Files:

- `evals/cases.ndjson`: one canonical Case Template and its Oracle
- `evals/rubric.json`: the 17-criterion scoring contract
- `tracecat/`: Candidate/Judge presets and workspace manifest
- `target/splunk/`: the only custom target image
- `assets/dataset/`: upstream dataset submodule
- `assets/Splunk.License`: user-supplied Splunk Enterprise license

After `just up 001`, open Splunk, create a least-privilege user allowed to
search only `investigation`, mint an encrypted MCP token in the installed MCP
Server app, and set `SPLUNK_MCP_AUTHORIZATION=Bearer <token>` in the root
`.env`. Terraform sends this header through a write-only provider attribute; it
is never stored in plan or state.

Run from the repository root:

```bash
git submodule update --init --recursive
just tracecat-up
just up 001
just init 001
just plan 001
just apply 001
just run 001
just judge 001 RUN_ID=<evaluation-run-id>
just export 001 RUN_ID=<evaluation-run-id>
```

The Candidate can use Case actions and the catalog Splunk MCP integration. It
cannot read tables, call arbitrary HTTP endpoints, start workflows, or use the
internet. The Judge has no tools and receives hidden evaluation material only
from Judge Run.
