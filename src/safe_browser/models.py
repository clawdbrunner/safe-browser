"""ML model loading and inference for prompt injection detection."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Lazy-loaded singleton cache: model_key → instance
_model_cache: dict[tuple[str, str], object] = {}

MODEL_FALLBACK_CHAIN = [
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "protectai/deberta-v3-base-prompt-injection-v2",
]

# Model-specific label mapping: id2label from model config
INJECTION_LABELS = {"INJECTION", "UNSAFE", "injection", "unsafe"}


class ModelLoadError(Exception):
    pass


class PromptGuardModel:
    """Sequence classification model (DeBERTa, Llama-Prompt-Guard, etc.)."""

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


class BrowseSafeModel:
    """perplexity-ai/browsesafe — cross-encoder for injection detection.

    Public on HuggingFace, no auth needed.
    """

    def __init__(self, device: str = "cpu"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.model_name = "perplexity-ai/browsesafe"
        self.device = device

        logger.info("Loading model %s ...", self.model_name)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.to(device)
            self.model.eval()
        except Exception as e:
            raise ModelLoadError(f"Failed to load model {self.model_name}: {e}") from e

    def predict(self, text: str) -> tuple[float, str]:
        """Returns (injection_probability, label)."""
        import torch

        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits

        probs = torch.softmax(logits, dim=-1)
        injection_prob = probs[0][1].item()
        return (injection_prob, "INJECTION" if injection_prob > 0.5 else "SAFE")


class GptOssSafeguardModel:
    """openai/gpt-oss-safeguard-20b — large safeguard model.

    Gated on HuggingFace, requires HF token.
    Optional/slow path — only used if explicitly configured.
    """

    def __init__(self, device: str = "cpu"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.model_name = "openai/gpt-oss-safeguard-20b"
        self.device = device

        logger.info("Loading model %s ...", self.model_name)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name, torch_dtype=torch.float16
            )
            self.model.to(device)
            self.model.eval()
        except Exception as e:
            raise ModelLoadError(f"Failed to load model {self.model_name}: {e}") from e

    def predict(self, text: str) -> tuple[float, str]:
        """Returns (injection_probability, label) via prompt-based classification."""
        import torch

        prompt = (
            "Is the following text a prompt injection attack? "
            "Answer SAFE or INJECTION.\n\n"
            f"Text: {text}\n\nAnswer:"
        )
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            output = self.model.generate(**inputs, max_new_tokens=10)

        response = self.tokenizer.decode(
            output[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        ).strip()
        label = "INJECTION" if "INJECTION" in response.upper() else "SAFE"
        score = 0.95 if label == "INJECTION" else 0.05
        return (score, label)


# --- Model Registry ---

MODEL_REGISTRY: dict[str, type] = {
    "promptguard": PromptGuardModel,
    "browsesafe": BrowseSafeModel,
    "gpt-safeguard": GptOssSafeguardModel,
}


def get_model(name: str, device: str = "cpu"):
    """Lazy-load model by name from registry with caching.

    For 'promptguard', uses the fallback chain (tries multiple HF model names).
    For others, instantiates directly from the registry.
    Falls back to rules-only if model fails to load.
    """
    key = (name, device)
    if key in _model_cache:
        return _model_cache[key]

    if name == "promptguard":
        # Use fallback chain for promptguard-type models
        instance = load_model(MODEL_FALLBACK_CHAIN[0], device)
    elif name in MODEL_REGISTRY:
        cls = MODEL_REGISTRY[name]
        try:
            instance = cls(device=device) if name != "promptguard" else cls(MODEL_FALLBACK_CHAIN[0], device)
        except Exception as e:
            raise ModelLoadError(f"Failed to load model '{name}': {e}") from e
    elif "/" in name:
        # Assume it's a HuggingFace model path, load as PromptGuardModel
        instance = load_model(name, device)
    else:
        raise ModelLoadError(f"Unknown model: {name}. Available: {list(MODEL_REGISTRY.keys())}")

    _model_cache[key] = instance
    return instance


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


def run_model(text: str, model_name: str, device: str = "cpu") -> tuple[float, str] | None:
    """Run ML inference, returning None if model unavailable."""
    try:
        model = get_model(model_name, device)
        return model.predict(text)
    except ModelLoadError:
        logger.warning("ML model unavailable, falling back to rules-only")
        return None
