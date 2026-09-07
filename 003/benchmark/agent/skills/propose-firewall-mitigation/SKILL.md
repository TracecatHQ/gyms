---
name: propose-firewall-mitigation
description: Use after exploitability is demonstrated to prepare and persist a narrow supplier intake ingress policy, its compatibility analysis, rollback conditions, and the human decision required to apply it.
---

# Propose firewall mitigation

Use this skill only after current case evidence demonstrates impact. Read scanner evidence, active verification results, benign transaction results, and the two existing case tasks. If active evidence is absent or incomplete, record the uncertainty and use **Verify exploitability** before recommending a control.

Call `security.supplier_intake.propose_policy` once to validate and persist the exact proposal on the case. Vulnerability intake authorizes this proposal action without human confirmation after verified impact; it does not authorize applying the proposal. Use the active case ID supplied in the invoking workflow's prompt and never ask a person to approve this action or copy the identifier. Supply a recommended mode and a concise rationale grounded in observed impact and compatibility. Keep the route, method, and allowed content type at their tool defaults:

| Field | Value |
| --- | --- |
| Route | `/form/supplier-intake` |
| Method | `POST` |
| Allowed content type | `multipart/form-data` |

Account for content-type parameters, header casing, and normalized route variants. Explain the demonstrated prerequisites and impact, affected route, expected blast radius, remaining application risk, uncertainties, and rollback conditions.

You have no firewall mutation tool. Do not execute the firewall workflow, write ModSecurity syntax, produce free-form firewall directives, propose IP blocks or global POST/JSON blocks, or provide shell commands or credentials. `Create BLOCK rule` and `Create LOG-only rule` are independently runnable human decisions bound to the persisted proposal. Automatic invocation by vulnerability intake does not change this authority boundary.

Add one durable recommendation led by: “I recommend a route-scoped content-type control. I need approval before applying it.” Use one compact table with `Status`, `Malice`, `Action`, and `Context` as columns. Follow it with no more than three bullets each under `What I found`, `What this means`, and `What I need from you`, then one compact `Evidence` table for the proposal ID, compatibility boundary, rollback path, remaining application risk, and sanitized references. Never include extracted secrets, raw exploit material, cookies, tokens, credentials, internal control endpoints, or secret-bearing logs.
