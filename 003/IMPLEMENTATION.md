# Vulnerability-driven firewall mitigation implementation record

This record describes the direct-action cutover implemented by this branch. A
fresh local stack verified the published scanner-intake webhook, automatic
Analyst scan/verification/proposal run, human-launched BLOCK task, deterministic
firewall evidence, automatic Analyst closure, and all 15 acceptance gates.

This exercise implements the vulnerability-driven firewall mitigation lifecycle for the
fixed `supplier.intake.test` scenario. It includes the isolated n8n target,
BunkerWeb control plane, reviewed Nuclei scan and exploitability probe, benign
traffic suite, Tracecat case/tasks/Analyst preset/skills/custom actions/workflows, evidence
retention, rollback, and active acceptance checks.

Tracecat presents one visible preset named `Analyst`, with the published skills
`Verify exploitability` and `Propose firewall mitigation`. The Analyst owns a
single case narrative. An upstream webhook or scheduled collector upserts the
case, then invokes **Investigate vulnerability scanner finding** with `case_id`,
source, and the bounded scanner verdict. The workflow runs the Analyst preset
and supplies the canonical case ID in its prompt. In that automatic run, the
Analyst records assignment, verifies impact, and persists a restricted mitigation
proposal that requests human review. It directly invokes the pinned, fixed-target
`scan`, `verify`, and `propose_policy` actions. The proposal action persists an
exact, revision-bound proposal on the case.

For a fresh local environment, the reconciler submits the seeded finding through
that published workflow's webhook after the case, preset, workflows, and tasks
exist, and waits for the proposal. A case-payload dispatch marker makes later
reconciles reuse the completed result instead of launching another Analyst run;
the webhook secret is used only in memory and is never persisted or printed.

The Analyst cannot write to the firewall. `Create LOG-only rule` and `Create
BLOCK rule` remain independently runnable case tasks. A person reviews the case
and chooses whether to run one. Both launch **Apply reviewed firewall rule**,
which records the result and automatically runs the Analyst preset with the
completed task evidence for closure review. No human chat prompt or copied case
identifier is part of the path.

The visible case is titled `Suspected unauthenticated n8n RCE on supplier intake`.
Customer-facing descriptions, comments, preset names, skills, workflows, tasks,
and screenshots use incident language rather than exercise identifiers. Internal
ownership metadata, source paths, and evaluation artifacts may retain the internal
identifier when it is not rendered in Tracecat.

Before the direct-action cutover, the ARM64 BunkerWeb custom-configuration gate proved create, activation, correlated
LOG and BLOCK events, removal, restoration, and final cleanup before the integrated
flow was exercised. All external images are immutable digest pins with official
provenance and seven-day cooldown metadata. The exercise adds no Python dependency.

The custom registry contract fixes the scenario, target, routes, command, policy
schema, and rule IDs. Tracecat injects credentials only into the action that
applies the reviewed proposal. Actions are bounded and return sanitized results.
Cleanup failure persists dirty state and blocks later probes until explicit reset.
Agent output cannot supply a URL, command, shell fragment, or raw firewall rule.
Evaluation expectations remain outside agent context, and evidence survives the
scenario reset.

There is no exercise-owned HTTP job service or polling API in the execution path.
Tracecat executes the registry actions on its executor and records their runs.
External components are limited to the pinned Nuclei binary, n8n application,
BunkerWeb control plane, receipt service, and independent acceptance harness.

Durable Analyst comments lead with a first-person conclusion and a single-row
table with `Status`, `Malice`, `Action`, and `Context` columns. At most three
short bullets under `What I found`, `What this means`, and `What I need from you`
follow, then one compact evidence table. Raw JSON is omitted. Raw exploit material, secrets,
credentials, cookies, internal control endpoints, and exercise terminology are
excluded. The final review distinguishes mitigation at the tested ingress from
remediation of the vulnerable application.

## Automation authority

| Actor | May do | May not do |
| --- | --- | --- |
| Upstream collector | Receive a finding, upsert its case, and invoke vulnerability intake with bounded inputs | Apply or select a firewall control |
| Vulnerability intake workflow | Supply the canonical case ID and run Analyst | Apply or select a firewall control |
| Analyst preset | Read and comment on the supplied case; run fixed-target scan, verify, and proposal actions; review completed task evidence | Execute workflows or mutate BunkerWeb |
| Human operator | Review the case and launch `Create LOG-only rule` or `Create BLOCK rule` | Supply hidden target, exploit, or firewall implementation inputs |
| Firewall workflow | Apply the exact persisted proposal for the launched task, verify it, roll back on failure, and run Analyst for closure review | Broaden the reviewed proposal or choose a task mode |

No commit, push, pull request, merge, or deletion outside this exercise was performed.
