"""Core scanning pipeline — merges rule-based and ML results."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Config
from .rules import RuleMatch, check_rules

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    decision: str  # "safe", "suspicious", "malicious"
    score: float  # 0.0 - 1.0 combined
    model_score: float | None = None
    model_label: str | None = None
    rule_matches: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        match self.decision:
            case "safe":
                return 0
            case "suspicious":
                return 1
            case "malicious":
                return 2
            case _:
                return 0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "score": round(self.score, 4),
            "model_score": round(self.model_score, 4) if self.model_score is not None else None,
            "model_label": self.model_label,
            "rule_matches": self.rule_matches,
            "details": self.details,
        }


def scan(text: str, config: Config) -> ScanResult:
    """Run the full scanning pipeline on the input text."""
    # 1. Rule-based checks (always, fast)
    rule_result = check_rules(text, config.custom_patterns if config.rules_enabled else None)
    rule_match_names = [m.name for m in rule_result.matches]
    rule_details = [
        {"name": m.name, "severity": m.severity, "matched": m.matched_text}
        for m in rule_result.matches
    ]

    # 2. ML model (if enabled)
    model_score: float | None = None
    model_label: str | None = None

    if config.use_ml:
        from .models import run_model

        result = run_model(text, config.model_name, config.device)
        if result is not None:
            model_score, model_label = result

    # 3. Merge results
    decision, score = _merge(rule_result, model_score, model_label, config)

    return ScanResult(
        decision=decision,
        score=score,
        model_score=model_score,
        model_label=model_label,
        rule_matches=rule_match_names,
        details={
            "rules": rule_details,
            "model": config.model_name if config.use_ml else "disabled",
            "thresholds": {
                "block": config.block_threshold,
                "caution": config.caution_threshold,
            },
        },
    )


def _merge(
    rule_result,
    model_score: float | None,
    model_label: str | None,
    config: Config,
) -> tuple[str, float]:
    """Merge rule and model results into a final decision and score."""
    # Rule HIGH + model says INJECTION → malicious
    if rule_result.has_high and model_score is not None and model_score >= config.block_threshold:
        return ("malicious", max(model_score, 0.95))

    # Rule HIGH alone → malicious
    if rule_result.has_high:
        return ("malicious", model_score if model_score is not None else 0.9)

    # Model says block → malicious
    if model_score is not None and model_score >= config.block_threshold:
        return ("malicious", model_score)

    # Rule MEDIUM or model caution → suspicious
    if rule_result.has_medium_or_above:
        return ("suspicious", model_score if model_score is not None else 0.6)

    if model_score is not None and model_score >= config.caution_threshold:
        return ("suspicious", model_score)

    # Low-severity rules with no model concern → suspicious (not malicious)
    if rule_result.matches:
        return ("suspicious", model_score if model_score is not None else 0.3)

    # All clear
    return ("safe", model_score if model_score is not None else 0.0)
