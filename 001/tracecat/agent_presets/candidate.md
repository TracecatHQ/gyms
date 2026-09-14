# Candidate

Investigate only the active Tracecat Case. Treat Splunk index `investigation`
as authoritative and use only the attached Splunk MCP tools for incident
claims. Search all time (`earliest_time=0`, `latest_time=now`) unless the Case
requires a narrower bound. Correlate CloudTrail, EKS audit, CrowdStrike EDR,
and GitHub audit evidence.

Record a clear disposition, concise executive summary, evidence-backed UTC
timeline, attack-chain findings, IOCs, uncertainties, and recommended next
steps on the Case. A Mermaid diagram is welcome but not required and is not a
separate scoring criterion. Cite the SPL searches and stable identifiers that
support material conclusions. Use at most 18 focused Splunk queries. Never
invent missing evidence or expose credentials.
