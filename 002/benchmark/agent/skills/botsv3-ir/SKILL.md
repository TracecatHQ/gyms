---
name: botsv3-ir
description: Use when investigating BOTSv3 demo alert cases in Tracecat — routes a triage to the right upstream AWS incident-response playbook skill (credential-compromise, data-access, api-security-breach, ransomware) and frames evidence gathering over the BOTSv3 log lake.
---

# BOTSv3 IR triage

Use this skill when investigating BOTSv3 demo alert cases in Tracecat.

## Evidence

- Start from the active case description, tags, and payload.
- Use DuckDB `read_json_auto` over the exact local MinIO gzip object in the case's `event_object_url` for supporting evidence.
- Search concrete indicators across the whole exact object before adding an outer `_time` filter. BOTSv3 journal rows can bundle embedded events whose event timestamp differs from the row's outer timestamp.
- Use read-only URLscan and VirusTotal enrichment after local evidence collection when concrete IOCs are present. If either UI-configured secret is unavailable, record the limitation and continue.
- Return bounded event metadata: `event_ref`, `event_time`, `_sourcetype`, `source`, and `host`.
- Do not paste full `_raw` records.
- Do not use hidden evaluator tables.
- Never submit URLs to URLscan; use existing-scan search and result retrieval only.

## Analysis

Follow the incident response cycle:

1. Acquire and preserve evidence.
2. Determine whether the alert is a true positive or false positive.
3. Enrich IOCs with reputation or scan context without replacing local event evidence.
4. Recommend containment only when evidence supports malicious activity.
5. Include eradication, recovery, and post-incident follow-up when malicious activity is confirmed.

## AWS IR playbook references

This skill package routes to standalone AWS incident-response playbook skills split under `../aws-irp-*`, with the original upstream AWS files preserved as each skill's `REFERENCE.md`. Use them as response-planning references, not as permission to perform live AWS changes.

BOTSv3 lab boundaries still apply:

- Do not use hidden evaluator tables.
- Do not mutate AWS accounts or production resources.
- Do not expose secrets, credentials, signed URLs, or full raw logs.
- Translate AWS playbook actions into simulated case next steps unless the user explicitly asks for a real-world runbook.

Route evidence to the AWS reference that best matches the case:

| Evidence pattern | Reference skill |
| --- | --- |
| GuardDuty IAM, suspicious AWS API calls, exposed/stolen access keys, unauthorized IAM activity | `aws-irp-credential-compromise` |
| S3 public access, bucket ACL/policy changes, S3 data exposure, bulk object access | `aws-irp-data-access` |
| API Gateway abuse, API key exposure, WAF/API authorizer issues, API scraping or BOLA/IDOR | `aws-irp-api-security-breach` |
| Ransom notes, encrypted files/objects/volumes, lockout or destructive encryption behavior | `aws-irp-ransomware` |
| Creating or improving new incident-response workflows rather than triaging a case | `aws-irp-playbook-builder` and `aws-irp-playbook-factory` |
| Multiple matched patterns | Use all relevant references and reconcile them into one case response plan. |

For non-AWS BOTSv3 cases, still borrow the AWS playbook structure where useful: evidence preservation, containment, eradication, recovery, stakeholder communication, and lessons learned.

## Output

Update the case description as the primary case artifact. Use concise Markdown with these sections:

```markdown
## Verdict

| Field | Value |
| --- | --- |
| Determination | true_positive / false_positive |
| Incident relevance | related / unrelated |
| Confidence | high / medium / low |

## Executive summary

Two or three sentences explaining what happened and why the case is being resolved or escalated.

## Timeline

| Time | Event | Evidence | MITRE tactic / technique |
| --- | --- | --- | --- |

## IoCs

| Type | Value | Context | Source |
| --- | --- | --- | --- |

## Evidence

| Evidence | Interpretation |
| --- | --- |

## Response plan

| Phase | Action |
| --- | --- |
```

After updating the description, add a short supplemental comment with the checked evidence sources and any caveat. Do not duplicate the full timeline, IoC table, or response plan in comments.

Preserve existing case tags and add compact closure tags:

- `verdict:true-positive` or `verdict:false-positive`
- `incident:related` or `incident:unrelated`

Do not use `botsv3_analyst_verdict` or `botsv3_breach_related` custom fields for new case state.
