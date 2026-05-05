"""Rule-based prompt injection detection."""

from __future__ import annotations

import re
from dataclasses import dataclass

RULES = [
    {
        "name": "ignore_instructions",
        "pattern": r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+instructions",
        "severity": "high",
    },
    {
        "name": "system_prompt_injection",
        "pattern": r"(?i)(you\s+are\s+now|system\s*prompt|new\s+instructions?)\s*[:=]",
        "severity": "high",
    },
    {
        "name": "role_switch",
        "pattern": r"(?i)(act\s+as|pretend\s+to\s+be|you\s+are\s+(?:now\s+)?DAN|jailbreak)",
        "severity": "high",
    },
    {
        "name": "data_exfil",
        "pattern": r"(?i)(send\s+(?:all\s+)?(?:emails?|data|passwords?|messages?)\s+to|forward\s+(?:all\s+)?(?:emails?|messages?)\s+to|exfiltrat|upload\s+(?:all\s+)?(?:user\s+)?data)",
        "severity": "high",
    },
    {
        "name": "hidden_unicode",
        "pattern": r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]",
        "severity": "medium",
    },
    {
        "name": "base64_encoded",
        "pattern": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
        "severity": "low",
    },
    {
        "name": "url_injection",
        "pattern": r"https?://[^\s<>\"]+\.(exe|zip|tar|gz|sh|bat|cmd|ps1)",
        "severity": "medium",
    },
]


@dataclass
class RuleMatch:
    name: str
    severity: str
    matched_text: str


@dataclass
class RuleResult:
    matches: list[RuleMatch]
    max_severity: str  # "none", "low", "medium", "high"

    @property
    def has_high(self) -> bool:
        return self.max_severity == "high"

    @property
    def has_medium_or_above(self) -> bool:
        return self.max_severity in ("high", "medium")


SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def check_rules(text: str, custom_patterns: list[dict] | None = None) -> RuleResult:
    """Run all rule-based checks against the input text."""
    all_rules = RULES + (custom_patterns or [])
    matches: list[RuleMatch] = []
    max_severity = "none"

    for rule in all_rules:
        pattern = rule["pattern"]
        try:
            found = re.search(pattern, text)
        except re.error:
            continue

        if found:
            match = RuleMatch(
                name=rule["name"],
                severity=rule["severity"],
                matched_text=found.group()[:100],  # truncate long matches
            )
            matches.append(match)
            if SEVERITY_ORDER.get(rule["severity"], 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = rule["severity"]

    return RuleResult(matches=matches, max_severity=max_severity)
