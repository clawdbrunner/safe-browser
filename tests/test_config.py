"""Tests for configuration loading."""

import tempfile
from pathlib import Path

import pytest
import yaml

from safe_browser.config import Config


class TestPhase1SingleModel:
    def test_default_config(self):
        config = Config()
        assert config.model_name == "promptguard"
        assert config.model_chain == ["promptguard"]

    def test_single_model_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({
            "model": {"name": "browsesafe", "device": "cpu"},
        }))
        config = Config.from_file(cfg_file)
        assert config.model_name == "browsesafe"
        assert config.model_chain == ["browsesafe"]

    def test_single_model_backward_compat(self):
        """Phase 1 config without models: list still works."""
        config = Config(model_name="gpt-safeguard")
        assert config.model_chain == ["gpt-safeguard"]


class TestPhase2ModelsList:
    def test_models_list_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({
            "models": [
                {"name": "rules", "priority": 0},
                {"name": "promptguard", "priority": 1, "threshold": 0.7},
                {"name": "browsesafe", "priority": 2, "threshold": 0.6},
            ],
        }))
        config = Config.from_file(cfg_file)
        assert len(config.models) == 3

    def test_model_chain_ordered_by_priority(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({
            "models": [
                {"name": "browsesafe", "priority": 2},
                {"name": "rules", "priority": 0},
                {"name": "promptguard", "priority": 1},
            ],
        }))
        config = Config.from_file(cfg_file)
        assert config.model_chain == ["rules", "promptguard", "browsesafe"]

    def test_model_chain_property_returns_list(self):
        config = Config(models=[
            {"name": "rules", "priority": 0},
            {"name": "promptguard", "priority": 1},
        ])
        chain = config.model_chain
        assert isinstance(chain, list)
        assert chain == ["rules", "promptguard"]

    def test_empty_models_list_falls_back(self):
        """When models: list is empty, fall back to model_name."""
        config = Config(model_name="promptguard", models=[])
        assert config.model_chain == ["promptguard"]

    def test_malformed_model_entry_skipped(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({
            "models": [
                {"name": "rules", "priority": 0},
                {"bad": "entry"},  # missing name
                {"name": "promptguard", "priority": 1},
            ],
        }))
        config = Config.from_file(cfg_file)
        assert len(config.models) == 2
        assert config.model_chain == ["rules", "promptguard"]
