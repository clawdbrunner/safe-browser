"""Tests for model registry and model classes."""

from unittest.mock import MagicMock, patch

import pytest

from safe_browser.models import (
    MODEL_REGISTRY,
    BrowseSafeModel,
    GptOssSafeguardModel,
    ModelLoadError,
    PromptGuardModel,
    get_model,
    run_model,
)


class TestModelRegistry:
    def test_registry_has_expected_keys(self):
        assert "promptguard" in MODEL_REGISTRY
        assert "browsesafe" in MODEL_REGISTRY
        assert "gpt-safeguard" in MODEL_REGISTRY

    def test_registry_maps_to_classes(self):
        assert MODEL_REGISTRY["promptguard"] is PromptGuardModel
        assert MODEL_REGISTRY["browsesafe"] is BrowseSafeModel
        assert MODEL_REGISTRY["gpt-safeguard"] is GptOssSafeguardModel

    def test_unknown_model_raises(self):
        with pytest.raises(ModelLoadError, match="Unknown model"):
            get_model("nonexistent-model")


class TestGetModel:
    def test_caches_model(self):
        mock_model = MagicMock()
        mock_model.predict.return_value = (0.1, "SAFE")

        with patch("safe_browser.models.load_model", return_value=mock_model) as mock_load:
            # Clear cache
            from safe_browser import models
            models._model_cache.clear()

            m1 = get_model("promptguard", "cpu")
            m2 = get_model("promptguard", "cpu")
            assert m1 is m2
            mock_load.assert_called_once()

    def test_different_key_reloads(self):
        mock_model_cpu = MagicMock()
        mock_model_mps = MagicMock()

        with patch("safe_browser.models.load_model", side_effect=[mock_model_cpu, mock_model_mps]):
            from safe_browser import models
            models._model_cache.clear()

            m1 = get_model("promptguard", "cpu")
            m2 = get_model("promptguard", "mps")
            assert m1 is not m2


class TestRunModel:
    def test_returns_prediction(self):
        mock_model = MagicMock()
        mock_model.predict.return_value = (0.85, "INJECTION")

        with patch("safe_browser.models.get_model", return_value=mock_model):
            result = run_model("test text", "promptguard")
        assert result == (0.85, "INJECTION")

    def test_returns_none_on_failure(self):
        with patch("safe_browser.models.get_model", side_effect=ModelLoadError("fail")):
            result = run_model("test text", "promptguard")
        assert result is None


class TestBrowseSafeModel:
    def test_predict_interface(self):
        """Test that BrowseSafeModel.predict returns (float, str) tuple."""
        mock_tokenizer = MagicMock()
        mock_model_obj = MagicMock()

        import torch

        # Mock model output
        mock_logits = torch.tensor([[0.2, 0.8]])
        mock_output = MagicMock()
        mock_output.logits = mock_logits
        mock_model_obj.return_value = mock_output
        mock_model_obj.to = MagicMock(return_value=mock_model_obj)
        mock_model_obj.eval = MagicMock(return_value=mock_model_obj)

        mock_tokenizer.return_value = {"input_ids": torch.tensor([[1, 2, 3]]), "attention_mask": torch.tensor([[1, 1, 1]])}

        with patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
             patch("transformers.AutoModelForSequenceClassification.from_pretrained", return_value=mock_model_obj):
            model = BrowseSafeModel(device="cpu")
            score, label = model.predict("test injection")

        assert isinstance(score, float)
        assert label in ("SAFE", "INJECTION")


class TestGptOssSafeguardModel:
    def test_predict_interface(self):
        """Test that GptOssSafeguardModel.predict returns (float, str) tuple."""
        mock_tokenizer = MagicMock()
        mock_model_obj = MagicMock()

        import torch

        # Mock tokenizer
        input_ids = torch.tensor([[1, 2, 3, 4, 5]])
        mock_tokenizer.return_value = {"input_ids": input_ids, "attention_mask": torch.tensor([[1, 1, 1, 1, 1]])}
        mock_tokenizer.decode.return_value = "INJECTION"

        # Mock model generate
        mock_model_obj.generate.return_value = torch.tensor([[1, 2, 3, 4, 5, 6, 7]])
        mock_model_obj.to = MagicMock(return_value=mock_model_obj)
        mock_model_obj.eval = MagicMock(return_value=mock_model_obj)

        with patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
             patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_model_obj):
            model = GptOssSafeguardModel(device="cpu")
            score, label = model.predict("test text")

        assert score == 0.95
        assert label == "INJECTION"

    def test_predict_safe(self):
        """Test safe prediction."""
        mock_tokenizer = MagicMock()
        mock_model_obj = MagicMock()

        import torch

        input_ids = torch.tensor([[1, 2, 3, 4, 5]])
        mock_tokenizer.return_value = {"input_ids": input_ids, "attention_mask": torch.tensor([[1, 1, 1, 1, 1]])}
        mock_tokenizer.decode.return_value = "SAFE"

        mock_model_obj.generate.return_value = torch.tensor([[1, 2, 3, 4, 5, 6, 7]])
        mock_model_obj.to = MagicMock(return_value=mock_model_obj)
        mock_model_obj.eval = MagicMock(return_value=mock_model_obj)

        with patch("transformers.AutoTokenizer.from_pretrained", return_value=mock_tokenizer), \
             patch("transformers.AutoModelForCausalLM.from_pretrained", return_value=mock_model_obj):
            model = GptOssSafeguardModel(device="cpu")
            score, label = model.predict("hello world")

        assert score == 0.05
        assert label == "SAFE"
