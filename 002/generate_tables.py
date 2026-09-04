#!/usr/bin/env python3
"""Generate BOTSv3 alert-case demo CSV seed tables.

The generator builds sparse provider-style alerts for Tracecat case creation,
plus hidden answer/outcome tables for evaluation. It reads the public BOTSv3
writeup and bounded metadata from the canonical ZIP, but it never
writes raw event payloads to generated CSVs.
"""

from __future__ import annotations

import argparse
import csv
import html
from html.parser import HTMLParser
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


WRITEUP_URL = "https://www.jamesgibbins.com/botsv3/"
DUCKDB_DEFAULT = "/Users/chris/.duckdb/cli/latest/duckdb"
MAX_EVENT_SAMPLES = 5

ALERTS_HEADER = [
    "alert_id",
    "provider",
    "product",
    "alert_type",
    "severity",
    "event_time",
    "resource",
    "status",
    "payload_json",
]
ANSWERS_HEADER = [
    "question_id",
    "question_text",
    "answer",
    "category",
    "scenario_phase",
    "source_url",
    "source_section",
]
OUTCOMES_HEADER = [
    "alert_id",
    "outcome",
    "breach_related",
    "expected_verdict",
    "related_question_ids",
    "evidence_filters",
    "notes",
    "false_positive_reason",
]

QUESTION_HEADING_RE = re.compile(r"^(?P<id>\d{3})\s+-\|-\s+(?P<text>.+)$")

# The public writeup has a few answer-adjacent blockquotes that are explanatory
# notes rather than the answer cell. Keep overrides explicit so the generated
# evaluator table stays deterministic without committing raw dataset evidence.
ANSWER_OVERRIDES = {
    "225": "index1.jpeg",
    "328": "Ubuntu 16.04.4 kernel priv esc",
}


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def clean_text(value: str) -> str:
    value = html.unescape(value)
    value = value.replace("\xa0", " ")
    value = value.replace("\u200b", "")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def duckdb_sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def create_view_sql(data_glob: str) -> str:
    return f"""
create or replace view botsv3_events as
select
  try_cast(_time as timestamp) as event_time,
  _sourcetype,
  source,
  host,
  _raw,
  hash(_time || '|' || _sourcetype || '|' || source || '|' || host || '|' || _raw) as event_ref
from read_json_auto({duckdb_sql_literal(data_glob)});
"""


def run_duckdb_json(duckdb_path: str, sql: str, cwd: Path) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [duckdb_path, "-json"],
        cwd=str(cwd),
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"DuckDB query failed: {proc.stderr.strip()}")
    output = proc.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def parse_duckdb_json_sets(output: str) -> list[list[dict[str, Any]]]:
    decoder = json.JSONDecoder()
    index = 0
    result_sets: list[list[dict[str, Any]]] = []
    while index < len(output):
        while index < len(output) and output[index].isspace():
            index += 1
        if index >= len(output):
            break
        value, index = decoder.raw_decode(output, index)
        result_sets.append(value)
    return result_sets


@dataclass
class QuestionBlock:
    question_id: str
    question_text: str
    source_section: str
    paragraphs: list[str] = field(default_factory=list)
    code_blocks: list[str] = field(default_factory=list)
    answers: list[str] = field(default_factory=list)

    @property
    def text_blob(self) -> str:
        return "\n".join(self.paragraphs + self.code_blocks + self.answers)


class WriteupParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.questions: list[QuestionBlock] = []
        self.current: QuestionBlock | None = None
        self.stack: list[str] = []
        self.h3_parts: list[str] = []
        self.h3_id = ""
        self.text_parts: list[str] = []
        self.capture_tag: str | None = None
        self.capture_answer = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.stack.append(tag)
        attr_map = {k: v or "" for k, v in attrs}
        if tag == "h3":
            self.h3_parts = []
            self.h3_id = attr_map.get("id", "")
        elif tag == "h2" and self.current is not None:
            self.current = None
        elif tag in {"p", "code"}:
            self.text_parts = []
            self.capture_tag = tag
            self.capture_answer = "blockquote" in self.stack
        elif tag == "pre":
            self.text_parts = []
            self.capture_tag = tag
            self.capture_answer = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "h3":
            heading = clean_text("".join(self.h3_parts))
            match = QUESTION_HEADING_RE.match(heading)
            if match:
                self.current = QuestionBlock(
                    question_id=match.group("id"),
                    question_text=match.group("text"),
                    source_section=self.h3_id,
                )
                self.questions.append(self.current)
            elif self.current is not None:
                self.current = None
        elif tag == self.capture_tag:
            text = clean_text("".join(self.text_parts))
            if text and self.current is not None:
                if self.capture_answer:
                    self.current.answers.append(text)
                elif tag in {"pre", "code"}:
                    self.current.code_blocks.append(text)
                else:
                    self.current.paragraphs.append(text)
            self.text_parts = []
            self.capture_tag = None
            self.capture_answer = False

        if self.stack:
            for index in range(len(self.stack) - 1, -1, -1):
                if self.stack[index] == tag:
                    del self.stack[index:]
                    break

    def handle_data(self, data: str) -> None:
        if "h3" in self.stack:
            self.h3_parts.append(data)
        if self.capture_tag is not None:
            self.text_parts.append(data)


def load_writeup_html(path: Path | None) -> str:
    if path:
        return path.read_text(encoding="utf-8")
    request = Request(WRITEUP_URL, headers={"User-Agent": "tracecat-botsv3-lab-generator/2.0"})
    try:
        with urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except URLError as exc:
        fallback = Path("assets/botsv3_writeup.html")
        if fallback.exists():
            return fallback.read_text(encoding="utf-8")
        raise SystemExit(
            f"failed to fetch {WRITEUP_URL}: {exc}. "
            "Pass --writeup-html or place a local cache at assets/botsv3_writeup.html."
        ) from exc


def parse_questions(html_text: str) -> list[QuestionBlock]:
    parser = WriteupParser()
    parser.feed(html_text)
    if not parser.questions:
        raise SystemExit("writeup parser found no question blocks")
    return parser.questions


def classify_question(block: QuestionBlock) -> tuple[str, str]:
    blob = f"{block.question_text} {block.text_blob}".lower()
    if any(term in blob for term in ["aws", "s3", "iam", "cloudtrail", "route 53", "bucket"]):
        return "aws", "AWS/web infrastructure activity"
    if any(term in blob for term in ["coin", "monero", "symantec", "endpoint", "chrome", "cpu", "miner"]):
        return "endpoint", "Endpoint coin-mining activity"
    if any(term in blob for term in ["onedrive", "o365", "azure", "mail", "bcc", "phishing", "aad"]):
        return "m365", "O365/OneDrive phishing and mail-rule activity"
    if any(term in blob for term in ["linux", "hoth", "tomcat", "cve", "root", "privilege", "colonel", "useradd"]):
        return "linux", "Linux/web exploitation and privilege escalation"
    if any(term in blob for term in ["vpn", "cisco", "brute force", "password spray", "c2", "command and control"]):
        return "network", "VPN and network activity"
    if any(term in blob for term in ["exfil", "customer", "deface", "memcached"]):
        return "impact", "Exfiltration or impact indicators"
    return "general", "General investigation context"


def build_answers(blocks: list[QuestionBlock]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for block in blocks:
        category, phase = classify_question(block)
        rows.append(
            {
                "question_id": block.question_id,
                "question_text": block.question_text,
                "answer": ANSWER_OVERRIDES.get(block.question_id, block.answers[0] if block.answers else ""),
                "category": category,
                "scenario_phase": phase,
                "source_url": f"{WRITEUP_URL}#{block.source_section}",
                "source_section": block.source_section,
            }
        )
    return rows


@dataclass(frozen=True)
class PublicAlert:
    """Analyst-visible projection of an AlertSpec, rendered into the alert payload. Holds no
    ground-truth/verdict field, so `base_payload` cannot leak the answer key."""

    alert_id: str
    provider: str
    product: str
    alert_type: str
    severity: str
    resource: str
    status: str
    query_terms: tuple[str, ...]
    notes: str
    rule_title: str
    tactic: str
    technique: str
    sample_offset: int
    sample_required_terms: tuple[str, ...]
    sample_any_terms: tuple[str, ...]
    rule_match_mode: str


@dataclass(frozen=True)
class AlertSpec:
    alert_id: str
    provider: str
    product: str
    alert_type: str
    severity: str
    resource: str
    status: str
    query_terms: tuple[str, ...]
    related_question_ids: tuple[str, ...]
    outcome: str
    breach_related: bool
    expected_verdict: str
    notes: str
    rule_title: str
    tactic: str
    technique: str
    false_positive_reason: str = ""
    sample_offset: int = 0
    sample_required_terms: tuple[str, ...] = ()
    sample_any_terms: tuple[str, ...] = ()
    rule_match_mode: str = "any"

    def public(self) -> "PublicAlert":
        """Project to the analyst-visible fields; the ground-truth fields are omitted."""
        return PublicAlert(
            alert_id=self.alert_id,
            provider=self.provider,
            product=self.product,
            alert_type=self.alert_type,
            severity=self.severity,
            resource=self.resource,
            status=self.status,
            query_terms=self.query_terms,
            notes=self.notes,
            rule_title=self.rule_title,
            tactic=self.tactic,
            technique=self.technique,
            sample_offset=self.sample_offset,
            sample_required_terms=self.sample_required_terms,
            sample_any_terms=self.sample_any_terms,
            rule_match_mode=self.rule_match_mode,
        )


ALERT_SPECS = [
    AlertSpec(
        "guardduty:s3-public-access",
        "guardduty",
        "Amazon GuardDuty",
        "Policy:S3/BucketAnonymousAccessGranted",
        "medium",
        "frothlywebcode",
        "active",
        ("frothlywebcode", "OPEN_BUCKET_PLEASE_FIX.txt"),
        ("203", "204", "205", "206"),
        "true_positive_breach",
        True,
        "True positive. Public S3 exposure is part of the breach path.",
        "S3 bucket exposure and public-window uploads.",
        "S3 bucket public access granted",
        "Exfiltration",
        "T1537",
    ),
    AlertSpec(
        "guardduty:iam-compromised-credentials",
        "guardduty",
        "Amazon GuardDuty",
        "AttackSequence:IAM/CompromisedCredentials",
        "high",
        "web_admin",
        "active",
        ("AKIAJOGCDXJ5NW5PXUPA", "web_admin"),
        ("200", "201", "218", "219", "220", "221", "222", "223"),
        "true_positive_breach",
        True,
        "True positive. Leaked IAM key activity is part of the breach path.",
        "Leaked AWS access key and unauthorized IAM/API attempts.",
        "Compromised IAM credentials used",
        "Credential Access",
        "T1552",
    ),
    AlertSpec(
        "guardduty:ec2-coinminer-dns",
        "guardduty",
        "Amazon GuardDuty",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "medium",
        "BSTOLL-L",
        "active",
        ("BSTOLL-L", "coinhive"),
        ("208", "210", "211", "216"),
        "true_positive_breach",
        True,
        "True positive. Coin-mining DNS/process evidence is part of the compromise.",
        "Cryptocurrency-mining DNS activity.",
        "EC2 DNS request to cryptocurrency mining domain",
        "Impact",
        "T1496",
        sample_required_terms=("BSTOLL-L", "coinhive"),
    ),
    AlertSpec(
        "guardduty:c2-contact",
        "guardduty",
        "Amazon GuardDuty",
        "Backdoor:EC2/C&CActivity.B!DNS",
        "high",
        "45.77.53.176",
        "active",
        ("45.77.53.176", "/admin/get.php"),
        ("322", "323"),
        "true_positive_breach",
        True,
        "True positive. C2 contact is part of the breach path.",
        "Endpoint traffic to adversary command-and-control infrastructure.",
        "EC2 host contacted command-and-control infrastructure",
        "Command and Control",
        "T1071",
        sample_required_terms=("45.77.53.176", "/admin/get.php"),
    ),
    AlertSpec(
        "wiz_defend:coinminer-runtime",
        "wiz",
        "Wiz Defend",
        "wiz.defend",
        "high",
        "BSTOLL-L",
        "active",
        ("BSTOLL-L", "chrome#5"),
        ("208", "210", "211", "212", "213", "214", "216"),
        "true_positive_breach",
        True,
        "True positive. Runtime coin-mining behavior is part of the compromise.",
        "Runtime process and DNS behavior consistent with coin mining.",
        "Runtime cryptocurrency miner behavior",
        "Impact",
        "T1496",
        sample_required_terms=("BSTOLL-L", "chrome#5"),
    ),
    AlertSpec(
        "wiz_defend:linux-rce-c2",
        "wiz",
        "Wiz Defend",
        "wiz.defend",
        "critical",
        "hoth",
        "active",
        ("hoth", "45.77.53.176"),
        ("303", "304", "305", "308", "314", "315", "316", "328", "333"),
        "true_positive_breach",
        True,
        "True positive. Linux RCE and C2 activity are part of the breach path.",
        "Remote command execution, tool staging, and C2 from Linux host hoth.",
        "Runtime command execution with external C2",
        "Execution",
        "T1059",
        sample_required_terms=("hoth", "45.77.53.176"),
    ),
    AlertSpec(
        "wiz_vulnerability:linux-cves",
        "wiz",
        "Wiz Vulnerability",
        "wiz.vulnerability",
        "critical",
        "hoth",
        "active",
        ("hoth", "colonel.c"),
        ("332", "333"),
        "true_positive_breach",
        True,
        "True positive. Vulnerable host context supports the breach investigation.",
        "Known Struts and Linux privilege-escalation CVEs tied to hoth.",
        "Exploitable vulnerability on Linux host",
        "Privilege Escalation",
        "T1068",
        sample_required_terms=("hoth", "colonel.c"),
    ),
    AlertSpec(
        "wiz_issue:public-s3-exposure",
        "wiz",
        "Wiz Issue",
        "wiz.issue",
        "high",
        "frothlywebcode",
        "active",
        ("frothlywebcode",),
        ("203", "204", "205", "206"),
        "true_positive_breach",
        True,
        "True positive. Cloud exposure issue is part of the breach path.",
        "Cloud risk issue for public S3 exposure.",
        "Public cloud storage exposed",
        "Exfiltration",
        "T1537",
    ),
    AlertSpec(
        "defender_cloud:linux-history-cleared",
        "defender_cloud",
        "Microsoft Defender for Cloud",
        "A history file has been cleared",
        "medium",
        "hoth",
        "active",
        ("hoth", ".bash_history"),
        ("328", "332", "333"),
        "true_positive_breach",
        True,
        "True positive. Anti-forensics follows Linux compromise activity.",
        "Shell history cleanup on compromised Linux host.",
        "Linux history file cleared",
        "Defense Evasion",
        "T1070",
        sample_required_terms=("hoth", ".bash_history"),
    ),
    AlertSpec(
        "defender_cloud:linux-suspicious-network",
        "defender_cloud",
        "Microsoft Defender for Cloud",
        "Detected suspicious network activity",
        "high",
        "hoth",
        "active",
        ("hoth", "nc 45.77.53.176"),
        ("305", "314", "315", "322", "323"),
        "true_positive_breach",
        True,
        "True positive. Suspicious external network activity is part of the breach path.",
        "Netcat/reverse-shell style network activity.",
        "Suspicious Linux network activity",
        "Command and Control",
        "T1105",
        sample_required_terms=("hoth", "nc 45.77.53.176"),
    ),
    AlertSpec(
        "sigma:m365-onedrive-lnk-upload",
        "sigma",
        "SIEM Sigma",
        "Suspicious OneDrive Link File Upload",
        "high",
        "BRUCE BIRTHDAY HAPPY HOUR PICS.lnk",
        "active",
        ("BRUCE BIRTHDAY HAPPY HOUR PICS.lnk",),
        ("300", "310", "312"),
        "true_positive_breach",
        True,
        "True positive. Suspicious OneDrive link upload is part of initial access.",
        "OneDrive upload of suspicious link file.",
        "Suspicious OneDrive link file upload",
        "Initial Access",
        "T1566",
    ),
    AlertSpec(
        "sigma:m365-onedrive-unusual-user-agent",
        "sigma",
        "SIEM Sigma",
        "Unusual OneDrive User Agent",
        "low",
        "OneDrive",
        "active",
        ("OneDrive", "UserAgent"),
        ("300",),
        "true_positive_breach",
        True,
        "Low-signal true positive. Needs correlation with file upload and endpoint activity.",
        "User-agent anomaly around OneDrive activity.",
        "Unusual OneDrive user agent",
        "Initial Access",
        "T1566",
        sample_required_terms=("OneDrive", "UserAgent"),
    ),
    AlertSpec(
        "sigma:m365-link-file-used",
        "sigma",
        "SIEM Sigma",
        "Suspicious Link File Accessed",
        "medium",
        "BRUCE BIRTHDAY HAPPY HOUR PICS.lnk",
        "active",
        ("BRUCE BIRTHDAY HAPPY HOUR PICS.lnk", "used"),
        ("312", "323"),
        "true_positive_breach",
        True,
        "True positive. Link-file usage is part of the compromise chain.",
        "Multiple users or IPs used the suspicious link file.",
        "Suspicious link file used",
        "Initial Access",
        "T1204",
        sample_required_terms=("BRUCE BIRTHDAY HAPPY HOUR PICS.lnk", "used"),
    ),
    AlertSpec(
        "sigma:m365-inbox-rule-forward-external",
        "sigma",
        "SIEM Sigma",
        "External Mail Forwarding Rule",
        "high",
        "hyunki1984@naver.com",
        "active",
        ("bcc", "hyunki1984@naver.com"),
        ("319",),
        "true_positive_breach",
        True,
        "True positive. External BCC forwarding rule is suspicious and breach-related.",
        "Mailbox forwarding/BCC rule to an external address.",
        "External mailbox forwarding rule",
        "Collection",
        "T1114",
        sample_required_terms=("bcc", "hyunki1984@naver.com"),
    ),
    AlertSpec(
        "sigma:m365-sensitive-mail-search",
        "sigma",
        "SIEM Sigma",
        "Suspicious Mail Search Terms",
        "medium",
        "mail search",
        "active",
        ("cromdale", "financial", "secret"),
        ("306",),
        "true_positive_breach",
        True,
        "True positive when correlated with phishing and endpoint activity.",
        "Suspicious search string from external IP context.",
        "Sensitive mail or web search terms",
        "Discovery",
        "T1213",
        sample_required_terms=("cromdale", "financial", "secret"),
    ),
    AlertSpec(
        "sigma:m365-expired-account-login",
        "sigma",
        "SIEM Sigma",
        "Successful Login To Expired Account",
        "medium",
        "expired account",
        "active",
        ("expired", "successful"),
        ("301",),
        "true_positive_breach",
        True,
        "True positive. Successful login to expired account is breach-related.",
        "Expired user account successful login.",
        "Successful sign-in by expired account",
        "Initial Access",
        "T1078",
        sample_required_terms=("expired", "successful"),
    ),
    AlertSpec(
        "sigma:m365-aad-password-reset-burst",
        "sigma",
        "SIEM Sigma",
        "Azure AD Password Reset Burst",
        "low",
        "Kevin Lagerfield",
        "active",
        ("Kevin Lagerfield", "password reset"),
        ("325",),
        "true_positive_non_breach",
        False,
        "Likely administrative noise unless correlated with the attack path.",
        "Multiple Azure AD password reset/change events.",
        "Azure AD password reset burst",
        "Credential Access",
        "T1098",
        sample_required_terms=("Kevin Lagerfield",),
    ),
    AlertSpec(
        "sigma:m365-aad-password-reset-burst-repeat-01",
        "sigma",
        "SIEM Sigma",
        "Azure AD Password Reset Burst",
        "low",
        "Kevin Lagerfield",
        "active",
        ("Kevin Lagerfield", "password reset"),
        ("325",),
        "true_positive_non_breach",
        False,
        "Likely administrative repeat noise unless correlated with the attack path.",
        "Repeated Azure AD password reset/change alert instance.",
        "Azure AD password reset burst",
        "Credential Access",
        "T1098",
        "",
        1,
        sample_required_terms=("Kevin Lagerfield",),
    ),
    AlertSpec(
        "sigma:m365-aad-account-disabled",
        "sigma",
        "SIEM Sigma",
        "Azure AD Account Disabled",
        "low",
        "bgist@froth.ly",
        "active",
        ("bgist@froth.ly", "disabled"),
        ("309",),
        "true_positive_non_breach",
        False,
        "Legitimate-looking account administration unless correlated with compromise.",
        "Azure AD account disabled by another user.",
        "Azure AD account disabled",
        "Impact",
        "T1531",
        sample_required_terms=("bgist@froth.ly", "disabled"),
    ),
    AlertSpec(
        "sigma:m365-aad-account-disabled-repeat-01",
        "sigma",
        "SIEM Sigma",
        "Azure AD Account Disabled",
        "low",
        "bgist@froth.ly",
        "active",
        ("bgist@froth.ly", "disabled"),
        ("309",),
        "true_positive_non_breach",
        False,
        "Repeated account-administration alert. Treat as noise unless correlated with compromise.",
        "Repeated Azure AD account-disabled alert instance.",
        "Azure AD account disabled",
        "Impact",
        "T1531",
        "",
        1,
        sample_required_terms=("bgist@froth.ly", "disabled"),
    ),
    AlertSpec(
        "sigma:m365-aad-account-disabled-repeat-02",
        "sigma",
        "SIEM Sigma",
        "Azure AD Account Disabled",
        "low",
        "bgist@froth.ly",
        "active",
        ("bgist@froth.ly", "disabled"),
        ("309",),
        "true_positive_non_breach",
        False,
        "Repeated account-administration alert. Treat as noise unless correlated with compromise.",
        "Repeated Azure AD account-disabled alert instance.",
        "Azure AD account disabled",
        "Impact",
        "T1531",
        "",
        2,
        sample_required_terms=("bgist@froth.ly", "disabled"),
    ),
    AlertSpec(
        "sigma:m365-email-malware-artifact",
        "sigma",
        "SIEM Sigma",
        "Email Malware Artifact",
        "high",
        "Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm",
        "active",
        ("Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm", "HxTsr.exe"),
        ("302", "310", "311"),
        "true_positive_breach",
        True,
        "True positive. Malware email artifact is part of the phishing chain.",
        "Malicious macro-enabled file and embedded executable artifact.",
        "Email malware artifact",
        "Initial Access",
        "T1566",
        sample_required_terms=("HxTsr.exe",),
    ),
    AlertSpec(
        "sigma:m365-log-ingestion-lag",
        "sigma",
        "SIEM Sigma",
        "AAD Sign-In Log Lag Anomaly",
        "info",
        "ms:aad:signin",
        "active",
        ("ms:aad:signin", "lag"),
        ("325",),
        "false_positive",
        False,
        "False positive for breach. It is an ingestion/telemetry delay question, not attacker behavior.",
        "Azure AD sign-in index/event creation lag.",
        "AAD sign-in ingestion lag anomaly",
        "Collection",
        "T1119",
        "Expected cloud log ingestion delay.",
        sample_required_terms=("ms:aad:signin", "lag"),
    ),
    AlertSpec(
        "sigma:m365-log-ingestion-lag-repeat-01",
        "sigma",
        "SIEM Sigma",
        "AAD Sign-In Log Lag Anomaly",
        "info",
        "ms:aad:signin",
        "active",
        ("ms:aad:signin", "lag"),
        ("325",),
        "false_positive",
        False,
        "False positive for breach. It is another ingestion/telemetry delay alert, not attacker behavior.",
        "Repeated Azure AD sign-in index/event creation lag alert instance.",
        "AAD sign-in ingestion lag anomaly",
        "Collection",
        "T1119",
        "Expected cloud log ingestion delay.",
        1,
        sample_required_terms=("ms:aad:signin", "lag"),
    ),
    AlertSpec(
        "sigma:m365-log-ingestion-lag-repeat-02",
        "sigma",
        "SIEM Sigma",
        "AAD Sign-In Log Lag Anomaly",
        "info",
        "ms:aad:signin",
        "active",
        ("ms:aad:signin", "lag"),
        ("325",),
        "false_positive",
        False,
        "False positive for breach. It is another ingestion/telemetry delay alert, not attacker behavior.",
        "Repeated Azure AD sign-in index/event creation lag alert instance.",
        "AAD sign-in ingestion lag anomaly",
        "Collection",
        "T1119",
        "Expected cloud log ingestion delay.",
        2,
        sample_required_terms=("ms:aad:signin", "lag"),
    ),
    AlertSpec(
        "sigma:vpn-high-traffic-user",
        "sigma",
        "SIEM Sigma",
        "High VPN Traffic User",
        "low",
        "mkraeusen",
        "active",
        ("mkraeusen", "cisco:asa"),
        ("330",),
        "false_positive",
        False,
        "False positive for breach unless correlated with attack infrastructure.",
        "High VPN traffic by user.",
        "High VPN traffic user",
        "Command and Control",
        "T1021",
        "High volume alone is normal-user noise in this lab.",
        sample_required_terms=("mkraeusen",),
    ),
    AlertSpec(
        "sigma:vpn-high-traffic-user-repeat-01",
        "sigma",
        "SIEM Sigma",
        "High VPN Traffic User",
        "low",
        "mkraeusen",
        "active",
        ("mkraeusen", "cisco:asa"),
        ("330",),
        "false_positive",
        False,
        "Repeated VPN volume alert. False positive for breach unless correlated with attack infrastructure.",
        "Repeated high VPN traffic alert instance.",
        "High VPN traffic user",
        "Command and Control",
        "T1021",
        "High volume alone is normal-user noise in this lab.",
        50,
        sample_required_terms=("mkraeusen",),
    ),
    AlertSpec(
        "sigma:vpn-high-traffic-user-repeat-02",
        "sigma",
        "SIEM Sigma",
        "High VPN Traffic User",
        "low",
        "mkraeusen",
        "active",
        ("mkraeusen", "cisco:asa"),
        ("330",),
        "false_positive",
        False,
        "Repeated VPN volume alert. False positive for breach unless correlated with attack infrastructure.",
        "Repeated high VPN traffic alert instance.",
        "High VPN traffic user",
        "Command and Control",
        "T1021",
        "High volume alone is normal-user noise in this lab.",
        200,
        sample_required_terms=("mkraeusen",),
    ),
    AlertSpec(
        "sigma:web-password-spray",
        "sigma",
        "SIEM Sigma",
        "Web Password Spray",
        "medium",
        "5.101.40.81",
        "active",
        ("5.101.40.81",),
        ("318",),
        "true_positive_non_breach",
        False,
        "True activity, but not necessarily part of the main breach path.",
        "Short brute-force/password-spray window against web servers.",
        "Web password spray",
        "Credential Access",
        "T1110",
    ),
    AlertSpec(
        "sigma:web-password-spray-repeat-01",
        "sigma",
        "SIEM Sigma",
        "Web Password Spray",
        "medium",
        "5.101.40.81",
        "active",
        ("5.101.40.81",),
        ("318",),
        "true_positive_non_breach",
        False,
        "Repeated true activity, but still not clearly part of the main breach path.",
        "Repeated short brute-force/password-spray alert instance.",
        "Web password spray",
        "Credential Access",
        "T1110",
        "",
        5,
    ),
    AlertSpec(
        "sigma:endpoint-hxtsr-from-macro",
        "sigma",
        "SIEM Sigma",
        "Suspicious Process From Macro Document",
        "high",
        "HxTsr.exe",
        "active",
        ("HxTsr.exe",),
        ("302", "310", "311"),
        "true_positive_breach",
        True,
        "True positive. Endpoint process is tied to malicious attachment activity.",
        "Suspicious process from macro-enabled file.",
        "Suspicious process spawned from macro document",
        "Execution",
        "T1204",
    ),
    AlertSpec(
        "sigma:endpoint-hdoor-network-scan",
        "sigma",
        "SIEM Sigma",
        "Endpoint Network Scan Tool",
        "high",
        "hdoor.exe",
        "active",
        ("hdoor.exe",),
        ("307", "317"),
        "true_positive_breach",
        True,
        "True positive. Network scan tool is part of attacker activity.",
        "Downloaded executable used to scan Frothly's network.",
        "Endpoint network scan tool",
        "Discovery",
        "T1046",
    ),
    AlertSpec(
        "sigma:linux-netcat-listener",
        "sigma",
        "SIEM Sigma",
        "Netcat Listener On Unusual Port",
        "high",
        "hoth:1337",
        "active",
        ("1337", "netcat"),
        ("305", "314", "315"),
        "true_positive_breach",
        True,
        "True positive. Netcat listener is part of Linux compromise activity.",
        "Netcat listening on unusual port.",
        "Netcat listener on unusual port",
        "Command and Control",
        "T1105",
        sample_required_terms=("1337", "netcat"),
    ),
    AlertSpec(
        "sigma:linux-uid0-user-created",
        "sigma",
        "SIEM Sigma",
        "Linux UID 0 User Created",
        "critical",
        "tomcat7",
        "active",
        ("useradd -ou 0", "tomcat7"),
        ("303", "304", "308"),
        "true_positive_breach",
        True,
        "True positive. Root-equivalent user creation is part of privilege escalation.",
        "Root-equivalent Linux user created after compromise.",
        "Linux UID 0 user created",
        "Privilege Escalation",
        "T1136",
        sample_required_terms=("useradd -ou 0", "tomcat7"),
    ),
]


def unique_terms(terms: tuple[str, ...] | list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for term in terms:
        if term and term not in seen:
            seen.add(term)
            result.append(term)
    return result


def term_predicate(term: str) -> str:
    return f"lower(_raw) like '%' || lower({duckdb_sql_literal(term)}) || '%'"


def build_terms_query(terms: tuple[str, ...] | list[str], match_mode: str = "any") -> str:
    predicates = [term_predicate(term) for term in terms]
    if not predicates:
        return "true"
    if match_mode == "all":
        return " and ".join(predicates)
    if match_mode == "any":
        return " or ".join(predicates)
    raise SystemExit(f"unsupported match mode: {match_mode}")


def sample_required_terms(spec: AlertSpec) -> list[str]:
    if spec.sample_required_terms:
        return unique_terms(spec.sample_required_terms)
    return unique_terms(spec.query_terms[:1])


def sample_any_terms(spec: AlertSpec) -> list[str]:
    return unique_terms(spec.sample_any_terms)


def build_sample_query(spec: AlertSpec) -> str:
    required = sample_required_terms(spec)
    any_terms = sample_any_terms(spec)
    clauses: list[str] = []
    if required:
        clauses.append(build_terms_query(required, "all"))
    if any_terms:
        clauses.append(f"({build_terms_query(any_terms, 'any')})")
    return " and ".join(clauses) if clauses else "true"


def collect_alert_evidence(
    specs: list[AlertSpec], duckdb_path: str, repo_root: Path, data_glob: str
) -> dict[str, dict[str, Any]]:
    statements = [create_view_sql(data_glob)]
    for index, spec in enumerate(specs):
        rule_clause = build_terms_query(spec.query_terms, spec.rule_match_mode)
        sample_clause = build_sample_query(spec)
        sample_terms = unique_terms(sample_required_terms(spec) + sample_any_terms(spec))
        sample_term_columns = ",\n  ".join(
            f"case when {term_predicate(term)} then true else false end as matched_term_{term_index}"
            for term_index, term in enumerate(sample_terms)
        )
        if sample_term_columns:
            sample_term_columns = ",\n  " + sample_term_columns
        statements.append(
            f"""
select
  {duckdb_sql_literal(spec.alert_id)} as alert_id,
  count(*) as rule_match_count,
  min(event_time)::varchar as rule_first_seen,
  max(event_time)::varchar as rule_last_seen
from botsv3_events
where {rule_clause};
"""
        )
        statements.append(
            f"""
select
  {duckdb_sql_literal(spec.alert_id)} as alert_id,
  count(*) as sample_match_count,
  min(event_time)::varchar as first_seen,
  max(event_time)::varchar as last_seen,
  list(distinct _sourcetype) as sourcetypes,
  list(distinct host) as hosts
from botsv3_events
where {sample_clause};
"""
        )
        statements.append(
            f"""
select
  {duckdb_sql_literal(spec.alert_id)} as alert_id,
  event_time::varchar as event_time,
  _sourcetype,
  source,
  host,
  event_ref::varchar as event_ref
  {sample_term_columns}
from botsv3_events
where {sample_clause}
order by event_time, event_ref
limit {MAX_EVENT_SAMPLES}
offset {spec.sample_offset};
"""
        )
    proc = subprocess.run(
        [duckdb_path, "-json"],
        cwd=str(repo_root),
        input="\n".join(statements),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"DuckDB evidence query failed: {proc.stderr.strip()}")

    result_sets = parse_duckdb_json_sets(proc.stdout)
    expected = len(specs) * 3
    if len(result_sets) != expected:
        raise SystemExit(f"expected {expected} DuckDB result sets, got {len(result_sets)}")

    evidence: dict[str, dict[str, Any]] = {}
    for index, spec in enumerate(specs):
        rule_rows = result_sets[index * 3]
        aggregate_rows = result_sets[index * 3 + 1]
        sample_rows = result_sets[index * 3 + 2]
        rule_aggregate = rule_rows[0] if rule_rows else {}
        aggregate = aggregate_rows[0] if aggregate_rows else {}
        sample_terms = unique_terms(sample_required_terms(spec) + sample_any_terms(spec))
        samples = [
            {
                "event_ref": row["event_ref"],
                "event_time": row["event_time"],
                "_sourcetype": row["_sourcetype"],
                "source": row["source"],
                "host": row["host"],
                "matched_terms": [
                    term for term_index, term in enumerate(sample_terms) if row.get(f"matched_term_{term_index}")
                ],
            }
            for row in sample_rows
        ]
        evidence[spec.alert_id] = {
            "event_count": int(aggregate.get("sample_match_count") or 0),
            "rule_match_count": int(rule_aggregate.get("rule_match_count") or 0),
            "rule_first_seen": rule_aggregate.get("rule_first_seen") or "",
            "rule_last_seen": rule_aggregate.get("rule_last_seen") or "",
            "first_seen": aggregate.get("first_seen") or "",
            "last_seen": aggregate.get("last_seen") or "",
            "sourcetypes": sorted(value for value in (aggregate.get("sourcetypes") or []) if value),
            "hosts": sorted(value for value in (aggregate.get("hosts") or []) if value),
            "samples": samples,
            "rule_terms": list(spec.query_terms),
            "rule_match_mode": spec.rule_match_mode,
            "sample_required_terms": sample_required_terms(spec),
            "sample_any_terms": sample_any_terms(spec),
        }
    return evidence


def base_payload(spec: PublicAlert, evidence: dict[str, Any]) -> dict[str, Any]:
    first_sample = evidence["samples"][0] if evidence["samples"] else {}
    matched_events = {
        "event_count": evidence["event_count"],
        "rule_match_count": evidence["rule_match_count"],
        "sample_match_count": evidence["event_count"],
        "sample_match_scope": {
            "required_terms": evidence["sample_required_terms"],
            "any_terms": evidence["sample_any_terms"],
        },
        "first_seen": evidence["first_seen"],
        "last_seen": evidence["last_seen"],
        "samples": evidence["samples"],
    }
    if spec.provider == "guardduty":
        return {
            "schemaVersion": "2.0",
            "id": spec.alert_id,
            "type": spec.alert_type,
            "severity": {"info": 1, "low": 2, "medium": 5, "high": 8, "critical": 9}.get(spec.severity, 5),
            "createdAt": first_sample.get("event_time") or spec_event_time(spec, evidence),
            "updatedAt": evidence["last_seen"] or spec_event_time(spec, evidence),
            "title": spec.rule_title,
            "description": spec.notes,
            "resource": provider_resource(spec),
            "service": {
                "serviceName": "guardduty",
                "action": guardduty_action(spec),
                "eventFirstSeen": evidence["first_seen"],
                "eventLastSeen": evidence["last_seen"],
                "count": evidence["rule_match_count"],
            },
            "matched_events": matched_events,
        }
    if spec.provider == "wiz":
        return {
            "@timestamp": first_sample.get("event_time") or spec_event_time(spec, evidence),
            "event": {"kind": "alert", "category": ["threat"], "dataset": spec.alert_type},
            "data_stream": {"type": "logs", "dataset": spec.alert_type, "namespace": "botsv3"},
            "cloud": {"provider": "aws"},
            "host": {"name": spec.resource},
            "wiz": {
                "alert": {"id": spec.alert_id, "name": spec.rule_title, "severity": spec.severity, "status": spec.status},
                "issue": {"type": spec.alert_type},
                # indicators are host/file terms, not CVEs — surface by name; cve stays [] unless present
                "vulnerability": {
                    "name": spec.rule_title,
                    "cve": [term for term in spec.query_terms if term.startswith("CVE-")],
                },
            },
            "matched_events": matched_events,
        }
    if spec.provider == "defender_cloud":
        return {
            "vendor": "Microsoft",
            "product": "Defender for Cloud",
            "alertType": spec.alert_type,
            "alertDisplayName": spec.rule_title,
            "severity": spec.severity,
            "timeGenerated": first_sample.get("event_time") or spec_event_time(spec, evidence),
            "resourceIdentifiers": [{"type": "host", "name": spec.resource}],
            "entities": [{"type": "host", "name": host} for host in evidence["hosts"][:5]],
            "description": spec.notes,
            "matchedEvents": matched_events,
        }
    return {
        "event": {"kind": "alert", "category": ["intrusion_detection"], "dataset": "sigma"},
        "rule": {
            "title": spec.rule_title,
            "level": spec.severity,
            "status": "test",
            "logsource": sigma_logsource(spec),
            "detection": {"keywords": list(spec.query_terms), "condition": spec.rule_match_mode},
        },
        "threat": {"tactic": {"name": spec.tactic}, "technique": {"id": spec.technique}},
        "query": f" {'OR' if spec.rule_match_mode == 'any' else 'AND'} ".join(spec.query_terms),
        "target": {"resource": spec.resource},
        "matched_events": matched_events,
    }


def spec_event_time(spec: PublicAlert, evidence: dict[str, Any]) -> str:
    if evidence["samples"]:
        return evidence["samples"][0]["event_time"]
    return evidence["first_seen"] or "2018-08-20 00:00:00"


def provider_resource(spec: PublicAlert) -> dict[str, Any]:
    if "S3" in spec.alert_type:
        return {"resourceType": "S3Bucket", "s3BucketDetails": [{"name": spec.resource}]}
    if "IAM" in spec.alert_type:
        return {"resourceType": "AccessKey", "accessKeyDetails": {"userName": spec.resource}}
    return {"resourceType": "Instance", "instanceDetails": {"instanceId": spec.resource}}


def guardduty_action(spec: PublicAlert) -> dict[str, Any]:
    if "DNS" in spec.alert_type:
        return {"actionType": "DNS_REQUEST", "dnsRequestAction": {"domain": spec.resource}}
    if "S3" in spec.alert_type:
        return {"actionType": "AWS_API_CALL", "awsApiCallAction": {"api": "PutBucketAcl", "serviceName": "s3.amazonaws.com"}}
    if "IAM" in spec.alert_type:
        return {"actionType": "AWS_API_CALL", "awsApiCallAction": {"api": "CreateAccessKey", "serviceName": "iam.amazonaws.com"}}
    return {"actionType": "NETWORK_CONNECTION", "networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": spec.resource}}}


def sigma_logsource(spec: PublicAlert) -> dict[str, str]:
    if ":m365-" in spec.alert_id:
        if "aad" in spec.alert_id or "expired-account" in spec.alert_id:
            return {"product": "m365", "service": "azuread"}
        if "inbox" in spec.alert_id or "mail" in spec.alert_id:
            return {"product": "m365", "service": "exchange"}
        return {"product": "m365", "service": "onedrive"}
    if "linux" in spec.alert_id:
        return {"product": "linux"}
    if "endpoint" in spec.alert_id:
        return {"product": "windows", "service": "sysmon"}
    if "vpn" in spec.alert_id:
        return {"product": "cisco", "service": "asa"}
    return {"category": "webserver"}


def build_alerts_and_outcomes(
    evidence_by_alert: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    alerts: list[dict[str, str]] = []
    outcomes: list[dict[str, str]] = []
    for spec in ALERT_SPECS:
        evidence = evidence_by_alert[spec.alert_id]
        if evidence["rule_match_count"] < 1:
            raise SystemExit(f"alert has no backing events: {spec.alert_id} terms={spec.query_terms}")
        if evidence["event_count"] < 1 or not evidence["samples"]:
            raise SystemExit(
                f"alert has no sampled evidence after offset: {spec.alert_id} "
                f"sample_required_terms={evidence['sample_required_terms']} sample_offset={spec.sample_offset}"
            )
        pub = spec.public()
        payload = base_payload(pub, evidence)
        event_time = spec_event_time(pub, evidence)
        alerts.append(
            {
                "alert_id": spec.alert_id,
                "provider": spec.provider,
                "product": spec.product,
                "alert_type": spec.alert_type,
                "severity": spec.severity,
                "event_time": event_time,
                "resource": spec.resource,
                "status": spec.status,
                "payload_json": compact_json(payload),
            }
        )
        outcomes.append(
            {
                "alert_id": spec.alert_id,
                "outcome": spec.outcome,
                "breach_related": str(spec.breach_related).lower(),
                "expected_verdict": spec.expected_verdict,
                "related_question_ids": compact_json(list(spec.related_question_ids)),
                "evidence_filters": compact_json(
                    {
                        "rule_terms": list(spec.query_terms),
                        "rule_match_mode": spec.rule_match_mode,
                        "rule_match_count": evidence["rule_match_count"],
                        "sample_required_terms": evidence["sample_required_terms"],
                        "sample_any_terms": evidence["sample_any_terms"],
                        "sample_match_count": evidence["event_count"],
                    }
                ),
                "notes": spec.notes,
                # Builder ground truth for false-positive alerts — hidden here, never in the
                # analyst-facing payload (see base_payload's sigma branch).
                "false_positive_reason": spec.false_positive_reason,
            }
        )
    return alerts, outcomes


def write_csv(path: Path, header: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="raise", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def validate_duckdb_corpus(duckdb_path: str, repo_root: Path, data_glob: str) -> None:
    sql = f"""
{create_view_sql(data_glob)}
select
  count(*) as events,
  min(event_time)::varchar as min_time,
  max(event_time)::varchar as max_time,
  count(distinct _sourcetype) as sourcetypes
from botsv3_events;
"""
    rows = run_duckdb_json(duckdb_path, sql, repo_root)
    if not rows or int(rows[0].get("events", 0)) != 489968:
        raise SystemExit(f"unexpected BOTSv3 event count: {rows}")


def validate_rows(
    alerts: list[dict[str, str]], answers: list[dict[str, str]], outcomes: list[dict[str, str]]
) -> None:
    valid_providers = {"guardduty", "wiz", "defender_cloud", "sigma"}
    alert_ids = [row["alert_id"] for row in alerts]
    if len(alert_ids) != len(set(alert_ids)):
        raise SystemExit("duplicate alert_id values")
    if any(row["provider"] not in valid_providers for row in alerts):
        raise SystemExit("unexpected provider in alerts")
    for row in alerts:
        payload = json.loads(row["payload_json"])
        if "_raw" in compact_json(payload):
            raise SystemExit(f"raw payload marker leaked into alert: {row['alert_id']}")
        matched_events = payload.get("matched_events") or payload.get("matchedEvents") or {}
        samples = matched_events.get("samples") or []
        if not samples:
            raise SystemExit(f"empty matched event samples in alert {row['alert_id']}")
        required_terms = matched_events.get("sample_match_scope", {}).get("required_terms") or []
        for sample in samples:
            matched_terms = set(sample.get("matched_terms") or [])
            missing_terms = [term for term in required_terms if term not in matched_terms]
            if missing_terms:
                raise SystemExit(f"sample missing required terms in {row['alert_id']}: {missing_terms}")
        for field_name in ALERTS_HEADER:
            if not row[field_name]:
                raise SystemExit(f"empty {field_name} in alert {row['alert_id']}")
    question_ids = [row["question_id"] for row in answers]
    if len(question_ids) != len(set(question_ids)):
        raise SystemExit("duplicate question_id values")
    outcome_ids = {row["alert_id"] for row in outcomes}
    if outcome_ids != set(alert_ids):
        raise SystemExit("outcomes do not exactly match alert IDs")
    noisy_count = sum(row["outcome"] in {"false_positive", "true_positive_non_breach"} for row in outcomes)
    if noisy_count < 12:
        raise SystemExit("expected at least 12 non-breach or false-positive alerts")
    first_sample_refs_by_family: dict[str, list[str]] = {}
    for row in alerts:
        family = row["alert_id"].split("-repeat-", 1)[0]
        if family == row["alert_id"] and not any(alert_id.startswith(f"{family}-repeat-") for alert_id in alert_ids):
            continue
        payload = json.loads(row["payload_json"])
        matched_events = payload.get("matched_events") or payload.get("matchedEvents") or {}
        first_ref = matched_events["samples"][0]["event_ref"]
        first_sample_refs_by_family.setdefault(family, []).append(first_ref)
    for family, refs in first_sample_refs_by_family.items():
        if len(refs) != len(set(refs)):
            raise SystemExit(f"repeat alert family reuses first sample ref: {family} {refs}")
    for row in outcomes:
        json.loads(row["related_question_ids"])
        json.loads(row["evidence_filters"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--writeup-html", type=Path, help="Optional ignored local cache of the BOTSv3 writeup HTML.")
    parser.add_argument("--duckdb", default=DUCKDB_DEFAULT, help="DuckDB CLI path.")
    parser.add_argument("--data-glob", help="Optional JSONL corpus glob. Defaults to temporary extraction from --archive.")
    parser.add_argument("--archive", type=Path, help="Canonical BOTSv3 ZIP (defaults to assets/botsv3-20260904T130332Z-1-001.zip).")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir
    duckdb_path = args.duckdb if Path(args.duckdb).exists() else "duckdb"

    temporary = None
    data_glob = args.data_glob
    if not data_glob:
        archive_path = (args.archive or script_dir / "assets/botsv3-20260904T130332Z-1-001.zip").resolve()
        temporary = tempfile.TemporaryDirectory(prefix="botsv3-generator-")
        with zipfile.ZipFile(archive_path) as archive:
            members = [name for name in archive.namelist() if name.startswith("botsv3/") and name.endswith(".jsonl.gz")]
            if len(members) != 71:
                raise SystemExit(f"expected 71 JSONL gzip members, found {len(members)}")
            archive.extractall(temporary.name, members)
        data_glob = str(Path(temporary.name) / "botsv3/*.jsonl.gz")

    html_text = load_writeup_html(args.writeup_html)
    blocks = parse_questions(html_text)
    answers = build_answers(blocks)
    evidence_by_alert = collect_alert_evidence(ALERT_SPECS, duckdb_path, repo_root, data_glob)
    alerts, outcomes = build_alerts_and_outcomes(evidence_by_alert)
    validate_rows(alerts, answers, outcomes)
    validate_duckdb_corpus(duckdb_path, repo_root, data_glob)

    data_dir = script_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    write_csv(data_dir / "alerts.csv", ALERTS_HEADER, alerts)
    write_csv(data_dir / "answers.csv", ANSWERS_HEADER, answers)
    write_csv(data_dir / "alert_outcomes.csv", OUTCOMES_HEADER, outcomes)

    if temporary is not None:
        temporary.cleanup()

    print(compact_json({"alerts": len(alerts), "answers": len(answers), "outcomes": len(outcomes)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
