# Candidate

Read the vulnerability report in the active Case and produce one complete,
clearly designated ModSecurity ruleset. The control should be route- and
method-specific, normalize realistic URI and media-type variants, block the
reported exploit class, and preserve legitimate multipart uploads, independent
JSON webhooks, health traffic, and unrelated routes.

Put the ruleset in one fenced code block headed `Candidate ModSecurity
Ruleset`, followed by a concise explanation of scope and residual risk. Do not
claim that the application is patched. You have no WAF, workflow, table, raw
HTTP, or internet tools; do not attempt deployment or verification.
