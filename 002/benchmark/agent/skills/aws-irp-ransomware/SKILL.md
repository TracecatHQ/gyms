---
name: aws-irp-ransomware
description: Use when a case involves ransomware indicators, ransom notes, encrypted files or objects, volume or object lockout, destructive encryption behavior, mass deletion, extortion, or compromise paths that could lead to ransomware impact.
---

# AWS IRP: ransomware

Use this skill when a case involves ransomware indicators, ransom notes, encrypted files or objects, volume or object lockout, destructive encryption behavior, mass deletion, extortion, or compromise paths that could lead to ransomware impact.

## Source

The full upstream AWS incident response playbook is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this as response-planning guidance only.
- Do not perform live AWS changes unless the user explicitly asks for an operational runbook outside the BOTSv3 lab.
- Do not use hidden evaluator tables.
- Do not disclose secrets, credentials, signed URLs, or full raw logs.
- Ground every case conclusion in local case context and DuckDB evidence before external enrichment.

## Response pattern

For ransomware cases, structure the response plan around:

1. Preserve evidence: affected hosts, volumes, buckets, ransom artifacts, process activity, identity activity, and earliest encryption or deletion time.
2. Contain: isolate hosts, disable compromised identities, block command-and-control paths, and prevent further object or volume changes.
3. Eradicate: remove malware, persistence, unauthorized credentials, attacker infrastructure, and backdoors.
4. Recover: restore from clean backups or versions, validate integrity, and reintroduce systems in a controlled sequence.
5. Post-incident: document root cause, backup posture, segmentation gaps, detection coverage, and stakeholder communications.

## Case output

When closing a Tracecat case, write the primary analysis in the case description with:

- Verdict table.
- Executive summary.
- Timeline table.
- IoC table for hosts, filenames, hashes when available, IPs, domains, principals, and affected resources.
- MITRE mapping where supported by evidence.
- Response plan table using preserve, contain, eradicate, recover, and lessons learned phases.
