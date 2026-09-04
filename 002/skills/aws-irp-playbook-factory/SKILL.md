---
name: aws-irp-playbook-factory
description: Use when converting an existing human-readable incident-response playbook into an AI-usable skill — playbook authoring and transformation work, not direct BOTSv3 case closure.
---

# AWS IRP: playbook factory

Use this skill when converting an existing human-readable incident-response playbook into an AI-usable skill. It is for playbook authoring and transformation work, not direct BOTSv3 case closure.

## Source

The full upstream AWS playbook-factory skill is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this for authoring new skills from existing playbooks, not for directly closing analyst cases.
- Keep analyst-facing instructions separate from builder/evaluator-only ground truth.
- Do not add hidden answer keys to analyst prompts.
- Do not perform live AWS changes.

## Authoring pattern

Follow the upstream factory process in `REFERENCE.md`:

1. Select the source playbook.
2. Extract incident type, triggers, phases, commands, and verification steps.
3. Convert human-centric steps into AI-operable instructions.
4. Add routing metadata and a quick reference.
5. Preserve safety notes, prerequisites, and references.
6. Validate that the output is specific enough for an agent to use without exposing secrets or hidden evaluator data.

When adapting output for this repo, keep each lab README updated with intent, data boundary, expected outcomes, and analyst-facing versus evaluator-only material.
