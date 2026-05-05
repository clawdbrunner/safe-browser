"""ML model loading and inference for prompt injection detection."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Lazy-loaded singleton
_model_instance: PromptGuardModel | None = None

MODEL_FALLBACK_CHAIN = [
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "protectai/deberta-v3-base-prompt-injection-v2",
]


class ModelLoadError(Exception):
    pass


class PromptGuardModel:
    def __init__(self, model_name: str, device: str = "cpu"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.model_name = model_name
        self.device = device

        logger.info("Loading model %s ...", model_name)
        print(f"Loading model {model_name}...", file=sys.stderr)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.to(device)
            self.model.eval()
        except Exception as e:
            raise ModelLoadError(f"Failed to load model {model_name}: {e}") from e

        self.num_labels = self.model.config.num_labels
        logger.info("Model loaded: %s (%d labels)", model_name, self.num_labels)

    def predict(self, text: str) -> tuple[float, str]:
        """Returns (injection_probability, label) where label is 'SAFE' or 'INJECTION'."""
        import torch

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits

        probs = torch.softmax(logits, dim=-1)

        # Both supported models use label index 1 for injection/unsafe
        injection_prob = probs[0][1].item() if self.num_labels >= 2 else probs[0][0].item()
        label = "INJECTION" if injection_prob > 0.5 else "SAFE"

        return (injection_prob, label)


def load_model(model_name: str, device: str = "cpu") -> PromptGuardModel:
    """Load the specified model, falling back through the chain if needed."""
    # Try requested model first
    names_to_try = [model_name] + [n for n in MODEL_FALLBACK_CHAIN if n != model_name]

    for name in names_to_try:
        try:
            return PromptGuardModel(name, device)
        except ModelLoadError as e:
            logger.warning("Could not load %s: %s", name, e)
            if name != names_to_try[-1]:
                logger.info("Trying next fallback model...")
            continue

    raise ModelLoadError("All models failed to load. Use rules-only mode.")


def get_model(model_name: str, device: str = "cpu") -> PromptGuardModel:
    """Get or create the cached model singleton."""
    global _model_instance
    if _model_instance is None or _model_instance.model_name != model_name:
        _model_instance = load_model(model_name, device)
    return _model_instance


def run_model(text: str, model_name: str, device: str = "cpu") -> tuple[float, str] | None:
    """Run ML inference, returning None if model unavailable."""
    try:
        model = get_model(model_name, device)
        return model.predict(text)
    except ModelLoadError:
        logger.warning("ML model unavailable, falling back to rules-only")
        return None
