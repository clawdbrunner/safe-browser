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
        "fail_closed": True,
    },
    "thresholds": {
        "block": 0.9,
        "caution": 0.5,
    },
    "rules": {
        "enabled": True,
        "custom_patterns": [],
    },
    "limits": {
        "max_input_bytes": 10 * 1024 * 1024,  # 10MB default
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
    fail_closed: bool = DEFAULTS["model"]["fail_closed"]
    block_threshold: float = DEFAULTS["thresholds"]["block"]
    caution_threshold: float = DEFAULTS["thresholds"]["caution"]
    rules_enabled: bool = DEFAULTS["rules"]["enabled"]
    custom_patterns: list[dict] = field(default_factory=list)
    use_ml: bool = True
    log_level: str = DEFAULTS["logging"]["level"]
    max_input_bytes: int = DEFAULTS["limits"]["max_input_bytes"]

    def __post_init__(self):
        """Validate config values."""
        if not 0.0 <= self.block_threshold <= 1.0:
            raise ValueError(f"block_threshold must be 0.0-1.0, got {self.block_threshold}")
        if not 0.0 <= self.caution_threshold <= 1.0:
            raise ValueError(f"caution_threshold must be 0.0-1.0, got {self.caution_threshold}")
        if self.caution_threshold >= self.block_threshold:
            raise ValueError(
                f"caution_threshold ({self.caution_threshold}) must be < block_threshold ({self.block_threshold})"
            )

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
        limits = raw.get("limits", {})
        log_cfg = raw.get("logging", {})

        # Validate custom patterns structure
        custom_patterns = rules.get("custom_patterns", [])
        if not isinstance(custom_patterns, list):
            logger.warning("custom_patterns must be a list, ignoring")
            custom_patterns = []
        validated_patterns = []
        for p in custom_patterns:
            if isinstance(p, dict) and "name" in p and "pattern" in p and "severity" in p:
                validated_patterns.append(p)
            else:
                logger.warning("Skipping malformed custom pattern: %s", p)

        try:
            return cls(
                model_name=model.get("name", DEFAULTS["model"]["name"]),
                device=model.get("device", DEFAULTS["model"]["device"]),
                fallback_to_rules=model.get("fallback_to_rules", DEFAULTS["model"]["fallback_to_rules"]),
                fail_closed=model.get("fail_closed", DEFAULTS["model"]["fail_closed"]),
                block_threshold=thresholds.get("block", DEFAULTS["thresholds"]["block"]),
                caution_threshold=thresholds.get("caution", DEFAULTS["thresholds"]["caution"]),
                rules_enabled=rules.get("enabled", DEFAULTS["rules"]["enabled"]),
                custom_patterns=validated_patterns,
                log_level=log_cfg.get("level", DEFAULTS["logging"]["level"]),
                max_input_bytes=limits.get("max_input_bytes", DEFAULTS["limits"]["max_input_bytes"]),
            )
        except ValueError as e:
            logger.warning("Config validation error: %s — using defaults", e)
            return cls()
