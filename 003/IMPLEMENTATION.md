# Gym 003 implementation record

Gym 003 implements the vulnerability-driven firewall mitigation lifecycle for the
fixed `supplier.intake.test` scenario. It includes the isolated n8n target,
BunkerWeb control plane, reviewed Nuclei scan and exploitability probe, benign
traffic suite, Tracecat case/tasks/Analyst preset/skills/workflows, evidence
retention, rollback, and active acceptance checks.

Tracecat presents one visible preset named `Analyst`, with the published skills
`Verify exploitability` and `Propose firewall mitigation`. The Analyst owns a
single case narrative: it records assignment, confirmed impact, a restricted
mitigation recommendation that requests human approval, and a closure assessment
after the operator runs the BLOCK task. The Analyst can run the reviewed
verification workflow and interpret sanitized evidence, but cannot write to the
firewall. `Test exploitability`, `Create LOG-only rule`, and `Create BLOCK rule`
remain independently runnable case tasks; firewall changes are human-launched.

The visible case is titled `Suspected unauthenticated n8n RCE on supplier intake`.
Customer-facing descriptions, comments, preset names, skills, workflows, tasks,
and screenshots use incident language rather than exercise identifiers. Internal
ownership metadata, source paths, and evaluation artifacts may retain the Gym 003
identifier when it is not rendered in Tracecat.

The ARM64 BunkerWeb custom-configuration gate proved create, activation, correlated
LOG and BLOCK events, removal, restoration, and final cleanup before the integrated
flow was exercised. All external images are immutable digest pins with official
provenance and seven-day cooldown metadata. The Gym adds no Python dependency.

The shared contract fixes the scenario, target, routes, command, policy schema,
rule IDs, and WAF credentials server-side. Jobs are asynchronous and bounded.
Cleanup failure persists dirty state and blocks later probes until explicit reset.
Agent output cannot supply a URL, command, shell fragment, or raw firewall rule.
Evaluation expectations remain outside agent context, and evidence survives the
scenario reset.

Durable Analyst comments lead with a first-person conclusion and separate SMAC
values for `Status`, `Malice`, `Action`, and `Context`, followed by what was
found, what it means, and what the operator needs to decide. Sanitized execution
references and technical evidence appear last. Raw exploit material, secrets,
credentials, cookies, internal control endpoints, and exercise terminology are
excluded. The final review distinguishes mitigation at the tested ingress from
remediation of the vulnerable application.

No commit, push, pull request, merge, or deletion outside Gym 003 was performed.
