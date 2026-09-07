---
name: propose-firewall-mitigation
description: Use after exploitability is demonstrated to prepare a narrow supplier intake ingress policy, its compatibility analysis, rollback conditions, and the human decision required to apply it.
---

# Propose firewall mitigation

Use this skill only after current case evidence demonstrates impact. Read scanner evidence, independent verification results, benign transaction results, the application route inventory, current rule observations, and the three existing case tasks. If active evidence is absent or incomplete, record the uncertainty and use **Verify exploitability** before recommending a control.

Propose only revision `1` of this structured ingress policy:

| Field | Value |
| --- | --- |
| Scenario | `supplier-intake` |
| Route | `/form/supplier-intake` |
| Method | `POST` |
| Allowed content type | `multipart/form-data` |

Account for content-type parameters, header casing, and normalized route variants. Check compatibility for the supplier multipart upload, independent JSON order webhook and downstream receipt, staff login, and health checks. Explain the demonstrated prerequisites and impact, affected route, expected blast radius, remaining application risk, uncertainties, and rollback conditions.

You have no authority or tool to change the firewall. Do not execute `gym-003-rule-application`, write ModSecurity syntax, produce free-form firewall directives, propose IP blocks or global POST/JSON blocks, or provide shell commands or credentials. `LOG_ONLY` is independently runnable and must never disable an existing BLOCK rule; it is not a prerequisite for BLOCK.

The internal alias is for permission scoping only. Never reproduce any alias beginning with `gym-003` in a case comment or handoff; refer to the controls as the `verification workflow` and `firewall workflow` in user-visible text.

Reference the three independently runnable tasks exactly once: `Create BLOCK rule` and `Create LOG-only rule` use the managed rule-application workflow with their respective modes; `Test exploitability` uses the managed verification workflow with `VERIFY_ONLY`. The reconciler owns task creation and binding, so do not create duplicate tasks.

Add one durable recommendation led by: “I recommend a route-scoped content-type control. I need approval before applying it.” Include the SMAC fields, `What I found`, `What this means`, and `What I need from you`, plus the compatibility boundary, rollback path, remaining application risk, and sanitized evidence references. Never include extracted secrets, raw exploit material, cookies, tokens, credentials, internal control endpoints, or secret-bearing logs.
