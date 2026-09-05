---
name: aws-irp-api-security-breach
description: Use when a case involves API Gateway abuse, API key exposure, API authentication or authorizer weakness, WAF/API alerts, abnormal API invocation volume, scraping, injection through API endpoints, BOLA/IDOR, or API-layer data exfiltration.
---

# AWS IRP: API security breach

Use this skill when a case involves API Gateway abuse, API key exposure, API authentication or authorizer weakness, WAF/API alerts, abnormal API invocation volume, scraping, injection through API endpoints, BOLA/IDOR, or API-layer data exfiltration.

## Source

The full upstream AWS incident response playbook is preserved in `REFERENCE.md`.

## BOTSv3 demo boundary

- Use this as response-planning guidance only.
- Do not perform live AWS changes unless the user explicitly asks for an operational runbook outside the BOTSv3 lab.
- Do not use hidden evaluator tables.
- Do not disclose secrets, credentials, signed URLs, or full raw logs.
- Ground every case conclusion in local case context and DuckDB evidence before external enrichment.

## Response pattern

For API-related cases, structure the response plan around:

1. Preserve evidence: affected API/stage, request timeline, caller IPs, auth context, WAF matches, CloudTrail changes, and backend impact.
2. Contain: throttle or disable abusive stages/routes, block attacker IPs or tokens, rotate exposed API keys, and restore authorizer or WAF controls.
3. Eradicate: remove unauthorized keys, repair API definitions, restore authorizer requirements, and remove attacker-created backend access.
4. Recover: re-enable legitimate API access, validate backend data integrity, and confirm CloudWatch/WAF metrics return to baseline.
5. Post-incident: update WAF rules, logging, API auth tests, rate limits, and owner notifications.

## Case output

When closing a Tracecat case, write the primary analysis in the case description with:

- Verdict table.
- Executive summary.
- Timeline table.
- IoC table for caller IPs, hostnames, API keys or key IDs when safe, routes, user agents, and backend resources.
- MITRE mapping where supported by evidence.
- Response plan table using preserve, contain, eradicate, recover, and lessons learned phases.
