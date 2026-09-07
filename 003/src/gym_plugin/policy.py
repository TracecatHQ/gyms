"""Restricted policy validation and deterministic ModSecurity rendering."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SCENARIO = "supplier-intake"
ASSET = "supplier.intake.test"
ROUTE = "/form/supplier-intake"
METHOD = "POST"
ALLOWED_TYPE = "multipart/form-data"
RULE_IDS = {"LOG_ONLY": 9300301, "BLOCK": 9300302}
CURRENT_PROPOSAL_REVISION = 1


@dataclass(frozen=True, slots=True)
class Policy:
    scenario: str
    revision: int
    route: str
    method: str
    allowed_content_type: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "revision": self.revision,
            "route": self.route,
            "method": self.method,
            "allowed_content_type": self.allowed_content_type,
        }


def validate_proposal(value: dict[str, Any], *, expected_revision: int) -> Policy:
    if set(value) != {"scenario", "revision", "route", "method", "allowed_content_type"}:
        raise ValueError("proposal has unknown or missing fields")
    policy = Policy(
        scenario=str(value["scenario"]),
        revision=int(value["revision"]),
        route=str(value["route"]),
        method=str(value["method"]).upper(),
        allowed_content_type=str(value["allowed_content_type"]).lower(),
    )
    expected = Policy(SCENARIO, expected_revision, ROUTE, METHOD, ALLOWED_TYPE)
    if policy != expected:
        raise ValueError("proposal is stale or outside the allowed supplier-upload policy")
    return policy


def render_modsecurity(policy: Policy, mode: str) -> tuple[int, str]:
    normalized_mode = mode.upper()
    if normalized_mode not in RULE_IDS:
        raise ValueError("rule mode must be BLOCK or LOG_ONLY")
    rule_id = RULE_IDS[normalized_mode]
    disruptive = "deny,status:403" if normalized_mode == "BLOCK" else "pass"
    message = f"gym003 supplier upload content type {normalized_mode.lower()}"
    # REQUEST_URI includes the raw query string. Match literal or percent-encoded
    # forms of every fixed path character because n8n accepts several equivalent
    # raw URI representations and this BunkerWeb release does not reliably apply
    # URL-decoding transforms to REQUEST_URI in a chained phase-one rule.
    path_pattern = "".join(
        "(?:/|%2f)"
        if character == "/"
        else f"(?:{re.escape(character)}|%{ord(character):02x})"
        for character in policy.route
    )
    rule = (
        f'SecRule REQUEST_URI "@rx (?i)^{path_pattern}(?:/|%2f)?(?:[?].*)?$" '
        f'"id:{rule_id},phase:1,{disruptive},log,auditlog,'
        f'msg:\'{message}\',tag:\'gym003\',tag:\'revision-{policy.revision}\',chain"\n'
        f'  SecRule REQUEST_METHOD "@streq {policy.method}" "chain"\n'
        '    SecRule REQUEST_HEADERS:Content-Type '
        '"!@rx (?i)^multipart/form-data(?:[[:space:]]*;|$)" "t:none"\n'
    )
    return rule_id, rule
