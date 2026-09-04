---
name: aws-irp-data-access
description: Use when a case involves unintended S3 access, public bucket or object exposure, permissive bucket policy or ACL changes, S3 GuardDuty/Macie findings, bulk object access, or data exposure through compromised credentials.
---

# AWS IRP: data access

Use this skill when a case involves unintended S3 access, public bucket or object exposure, permissive bucket policy or ACL changes, S3 GuardDuty/Macie findings, bulk object access, or data exposure through compromised credentials.

## Source

The full upstream AWS incident response playbook is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this as response-planning guidance only.
- Do not perform live AWS changes unless the user explicitly asks for an operational runbook outside the BOTSv3 lab.
- Do not use hidden evaluator tables.
- Do not disclose secrets, credentials, signed URLs, or full raw logs.
- Ground every case conclusion in local case context and DuckDB evidence before external enrichment.

## Response pattern

For data-access cases, structure the response plan around:

1. Preserve evidence: affected bucket/object scope, access vector, requester identity, source IPs, object access timeline, and data classification.
2. Contain: enable Block Public Access, remove permissive ACLs or policies, disable compromised credentials, and stop ongoing exfiltration.
3. Eradicate: harden bucket policies, rotate credentials, remove unauthorized principals, and close related instance or identity exposure paths.
4. Recover: restore object integrity from versioning/backups where needed and validate legitimate application access.
5. Post-incident: update data classification, Macie/GuardDuty coverage, policy guardrails, owner communications, and notification requirements.

## Case output

When closing a Tracecat case, write the primary analysis in the case description with:

- Verdict table.
- Executive summary.
- Timeline table.
- IoC table for buckets, object prefixes, principals, IPs, user agents, and safe access key identifiers.
- MITRE mapping where supported by evidence.
- Response plan table using preserve, contain, eradicate, recover, and lessons learned phases.
