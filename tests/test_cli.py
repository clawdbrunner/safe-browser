"""Tests for CLI validation."""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from safe_browser.cli import VALID_ADAPTERS, VALID_MODELS, app

runner = CliRunner()


class TestAdapterValidation:
    def test_valid_adapter_auto(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "auto"])
        assert result.exit_code == 0

    def test_valid_adapter_camoufox(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "camoufox"])
        # May fail on non-JSON input, but shouldn't fail on validation
        assert "invalid adapter" not in (result.output or "")

    def test_valid_adapter_raw(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "raw"])
        assert result.exit_code == 0

    def test_valid_adapter_agent_browser_hyphen(self):
        """agent-browser (with hyphen) should be accepted and normalized."""
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "agent-browser"])
        assert result.exit_code == 0

    def test_valid_adapter_agent_browser_underscore(self):
        """agent_browser (with underscore) should be accepted."""
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "agent_browser"])
        assert result.exit_code == 0

    def test_invalid_adapter_rejected(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "firefox"])
        assert result.exit_code == 2
        assert "invalid adapter" in result.output.lower()

    def test_invalid_adapter_lists_valid_options(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--adapter", "bad"])
        assert result.exit_code == 2
        assert "auto" in result.output
        assert "camoufox" in result.output
        assert "raw" in result.output


class TestModelValidation:
    def test_valid_model_promptguard(self):
        with patch("safe_browser.models.run_model", return_value=(0.1, "SAFE")):
            result = runner.invoke(app, ["check", "-c", "hello", "--model", "promptguard"])
        assert result.exit_code == 0

    def test_valid_model_rules(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--model", "rules"])
        assert result.exit_code == 0

    def test_valid_model_browsesafe(self):
        with patch("safe_browser.models.run_model", return_value=(0.1, "SAFE")):
            result = runner.invoke(app, ["check", "-c", "hello", "--model", "browsesafe"])
        assert result.exit_code == 0

    def test_valid_model_gpt_safeguard(self):
        with patch("safe_browser.models.run_model", return_value=(0.1, "SAFE")):
            result = runner.invoke(app, ["check", "-c", "hello", "--model", "gpt-safeguard"])
        assert result.exit_code == 0

    def test_invalid_model_rejected(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--model", "gpt4"])
        assert result.exit_code == 2
        assert "invalid model" in result.output.lower()

    def test_invalid_model_lists_valid_options(self):
        result = runner.invoke(app, ["check", "-c", "hello", "--model", "bad"])
        assert result.exit_code == 2
        assert "promptguard" in result.output
        assert "browsesafe" in result.output
        assert "rules" in result.output
