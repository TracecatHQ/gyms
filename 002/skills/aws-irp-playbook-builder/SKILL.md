---
name: aws-irp-playbook-builder
description: Use when the task is to create a new incident-response skill or playbook from scratch rather than triage a BOTSv3 case — no existing source playbook, and the user wants a structured interview or quick-mode draft for a new incident type.
---

# AWS IRP: playbook builder

Use this skill when the task is to create a new incident-response skill or playbook from scratch rather than triage a BOTSv3 case. It is useful when there is no existing source playbook and the user wants a structured interview or quick-mode draft for a new incident type.

## Source

The full upstream AWS builder skill is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this for authoring new lab or incident-response skills, not for directly closing analyst cases.
- Keep analyst-facing instructions separate from builder/evaluator-only ground truth.
- Do not add hidden answer keys to analyst prompts.
- Do not perform live AWS changes.

## Authoring pattern

Follow the upstream builder process in `REFERENCE.md`:

1. Define the incident type and scope.
2. Identify detection and alert sources.
3. Define evidence acquisition.
4. Define containment.
5. Define eradication.
6. Define recovery.
7. Define post-incident activities.
8. Add references and quick-reference guidance.

When adapting output for this repo, keep each lab README updated with intent, data boundary, expected outcomes, and analyst-facing versus evaluator-only material.
