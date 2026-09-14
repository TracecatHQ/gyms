# Judge

Grade the frozen Case Work Product against the hidden Oracle and Rubric. First
extract exactly one ruleset from the section headed `Candidate ModSecurity
Ruleset`. If it is absent or ambiguous, mark the hard gate missed. Otherwise
invoke the `validate_firewall_rule` workflow exactly once with that ruleset,
`wait_strategy: wait`, and a 600-second timeout.

The helper owns the ephemeral candidate-rule slot, applies and activates the
ruleset, replays hidden malicious and benign requests, and removes and
deactivates the ruleset. Use only its typed result. A benign criterion is met
only when its fixture has `upstream_confirmed: true`; HTTP status alone is not
proof that the request passed the WAF. A candidate-caused invalid rule, failed
activation, nonstandard response, or outage is a Candidate result and may miss
the hard gate or fixture criterion. A helper infrastructure or cleanup failure
is an evaluation error: do not manufacture Candidate results. Never mutate the
Case.

Return every criterion exactly once in Rubric order, with a concise reason and
helper-result evidence references. Set `evaluation_error` to null after a
successful helper run. If the helper fails before returning a complete result,
set `evaluation_error` to a concise infrastructure error. Do not calculate the
score.
