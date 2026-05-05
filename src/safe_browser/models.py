"""ML model loading and inference for prompt injection detection."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Lazy-loaded singleton
_model_instance: PromptGuardModel | None = None
_model_key: tuple[str, str] | None = None  # (model_name, device)

MODEL_FALLBACK_CHAIN = [
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "protectai/deberta-v3-base-prompt-injection-v2",
]

# Model-specific label mapping: id2label from model config
# Some models label injection as index 1, others use different indices
INJECTION_LABELS = {"INJECTION", "UNSAFE", "injection", "unsafe"}


class ModelLoadError(Exception):
    pass


class PromptGuardModel:
    def __init__(self, model_name: str, device: str = "cpu"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.model_name = model_name
        self.device = device

        logger.info("Loading model %s ...", model_name)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.to(device)
            self.model.eval()
        except Exception as e:
            raise ModelLoadError(f"Failed to load model {model_name}: {e}") from e

        self.num_labels = self.model.config.num_labels
        self.id2label = getattr(self.model.config, "id2label", {})

        # Determine injection index from model config
        self._injection_idx = self._find_injection_index()
        logger.info("Model loaded: %s (%d labels, injection_idx=%d)", model_name, self.num_labels, self._injection_idx)

    def _find_injection_index(self) -> int:
        """Find the label index corresponding to injection/unsafe."""
        for idx, label in self.id2label.items():
            if label in INJECTION_LABELS:
                return int(idx)
        # Default: index 1 is injection for most classifiers
        return 1

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

        injection_prob = probs[0][self._injection_idx].item()
        label = "INJECTION" if injection_prob > 0.5 else "SAFE"

        return (injection_prob, label)


def load_model(model_name: str, device: str = "cpu") -> PromptGuardModel:
    """Load the specified model, falling back through the chain if needed."""
    names_to_try = [model_name] + [n for n in MODEL_FALLBACK_CHAIN if n != model_name]

    for name in names_to_try:
        try:
            return PromptGuardModel(name, device)
        except ModelLoadError as e:
            logger.warning("Could not load %s: %s", name, e)
            if name != names_to_try[-1]:
                logger.info("Trying next fallback model...")
            continue

    raise ModelLoadError("All models failed to load. Use --no-ml for rules-only mode.")


def get_model(model_name: str, device: str = "cpu") -> PromptGuardModel:
    """Get or create the cached model singleton. Reloads if model or device changes."""
    global _model_instance, _model_key
    key = (model_name, device)
    if _model_instance is None or _model_key != key:
        _model_instance = load_model(model_name, device)
        _model_key = key
    return _model_instance


def run_model(text: str, model_name: str, device: str = "cpu") -> tuple[float, str] | None:
    """Run ML inference, returning None if model unavailable."""
    try:
        model = get_model(model_name, device)
        return model.predict(text)
    except ModelLoadError:
        logger.warning("ML model unavailable, falling back to rules-only")
        return None
