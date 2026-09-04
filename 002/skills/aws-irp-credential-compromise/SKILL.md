---
name: aws-irp-credential-compromise
description: Use when a case involves compromised AWS credentials, leaked or exposed IAM access keys, suspicious STS use, unauthorized IAM activity, GuardDuty IAM findings, unusual AWS API calls, or attacker persistence through IAM users, roles, policies, or access keys.
---

# AWS IRP: credential compromise

Use this skill when a case involves compromised AWS credentials, leaked or exposed IAM access keys, suspicious STS use, unauthorized IAM activity, GuardDuty IAM findings, unusual AWS API calls, or attacker persistence through IAM users, roles, policies, or access keys.

## Source

The full upstream AWS incident response playbook is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this as response-planning guidance only.
- Do not perform live AWS changes unless the user explicitly asks for an operational runbook outside the BOTSv3 lab.
- Do not use hidden evaluator tables.
- Do not disclose secrets, credentials, signed URLs, or full raw logs.
- Ground every case conclusion in local case context and DuckDB evidence before external enrichment.

## Response pattern

For credential cases, structure the response plan around:

1. Preserve evidence: access key ID or safe key fingerprint, principal, API timeline, source IPs, affected accounts, and first/last seen activity.
2. Contain: disable or revoke compromised credentials, block active sessions where possible, and restrict affected principals.
3. Eradicate: remove attacker-created IAM users, keys, roles, policies, trust relationships, and persistence.
4. Recover: restore legitimate application access with rotated credentials and validate that affected resources are functioning.
5. Post-incident: review credential exposure path, detection gaps, key rotation practices, least privilege, and owner notifications.

## Case output

When closing a Tracecat case, write the primary analysis in the case description with:

- Verdict table.
- Executive summary.
- Timeline table.
- IoC table for safe access key identifiers, principals, source IPs, user agents, regions, and affected resources.
- MITRE mapping where supported by evidence.
- Response plan table using preserve, contain, eradicate, recover, and lessons learned phases.
