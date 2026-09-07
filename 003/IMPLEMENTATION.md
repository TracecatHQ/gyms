# Gym 003 implementation record

Gym 003 implements the vulnerability-driven firewall mitigation lifecycle for the
fixed `supplier.intake.test` scenario. It includes the isolated n8n target,
BunkerWeb control plane, reviewed Nuclei scan and exploitability probe, benign
traffic suite, Tracecat case/tasks/presets/workflows, evidence retention, rollback,
and active acceptance checks.

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

No commit, push, pull request, merge, or deletion outside Gym 003 was performed.
