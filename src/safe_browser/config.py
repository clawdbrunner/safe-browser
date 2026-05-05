"""Configuration loading and defaults."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "safe-browser" / "config.yaml"

DEFAULTS = {
    "model": {
        "name": "protectai/deberta-v3-base-prompt-injection-v2",
        "device": "cpu",
        "fallback_to_rules": True,
    },
    "thresholds": {
        "block": 0.9,
        "caution": 0.5,
    },
    "rules": {
        "enabled": True,
        "custom_patterns": [],
    },
    "logging": {
        "level": "WARNING",
    },
}


@dataclass
class Config:
    model_name: str = DEFAULTS["model"]["name"]
    device: str = DEFAULTS["model"]["device"]
    fallback_to_rules: bool = DEFAULTS["model"]["fallback_to_rules"]
    block_threshold: float = DEFAULTS["thresholds"]["block"]
    caution_threshold: float = DEFAULTS["thresholds"]["caution"]
    rules_enabled: bool = DEFAULTS["rules"]["enabled"]
    custom_patterns: list[dict] = field(default_factory=list)
    use_ml: bool = True
    log_level: str = DEFAULTS["logging"]["level"]

    @classmethod
    def from_file(cls, path: Path | None = None) -> Config:
        config_path = path or DEFAULT_CONFIG_PATH
        if not config_path.exists():
            logger.debug("No config file at %s, using defaults", config_path)
            return cls()

        try:
            raw = yaml.safe_load(config_path.read_text())
        except Exception as e:
            logger.warning("Failed to read config %s: %s — using defaults", config_path, e)
            return cls()

        if not isinstance(raw, dict):
            return cls()

        model = raw.get("model", {})
        thresholds = raw.get("thresholds", {})
        rules = raw.get("rules", {})
        log_cfg = raw.get("logging", {})

        return cls(
            model_name=model.get("name", DEFAULTS["model"]["name"]),
            device=model.get("device", DEFAULTS["model"]["device"]),
            fallback_to_rules=model.get("fallback_to_rules", DEFAULTS["model"]["fallback_to_rules"]),
            block_threshold=thresholds.get("block", DEFAULTS["thresholds"]["block"]),
            caution_threshold=thresholds.get("caution", DEFAULTS["thresholds"]["caution"]),
            rules_enabled=rules.get("enabled", DEFAULTS["rules"]["enabled"]),
            custom_patterns=rules.get("custom_patterns", []),
            log_level=log_cfg.get("level", DEFAULTS["logging"]["level"]),
        )
