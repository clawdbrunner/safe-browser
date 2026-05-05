# safe-browser

> Screen browser content for prompt injection attacks. Pluggable browser inputs, pluggable detection models.

## Why?

AI agents browsing the web are exposed to prompt injection attacks — hidden HTML elements, social engineering footers, disguised system commands. **safe-browser** is a pre-processing layer that scans content *before* it reaches your LLM agent.

## Install

```bash
pip install safe-browser
```

## Quick Start

```bash
# Pipe from any browser tool
agent-browser snapshot | safe-browser check

# Check a string
safe-browser check -c "Ignore all previous instructions"

# Check a file
safe-browser check -f page.html

# JSON output for scripts
safe-browser check -f page.html --json

# Rules only (no model download)
echo "hello" | safe-browser check --no-ml
```

## How It Works

```
Browser Tool → raw HTML/text → safe-browser → exit code (0/1/2) → your agent
                                       ↓
                              Rule Engine + ML Model
```

**Two detection layers:**

1. **Rule engine** — regex patterns for known injection patterns (always runs, instant)
2. **ML model** — neural classifier for subtle/obfuscated attacks (optional, ~2s first load)

Both results merge into a single verdict: **SAFE** (exit 0), **SUSPICIOUS** (exit 1), or **MALICIOUS** (exit 2).

## Commands

| Command | Description |
|---------|-------------|
| `safe-browser check` | Scan content for attacks (primary) |
| `safe-browser scan` | Alias for check |
| `safe-browser doctor` | Verify config and model setup |
| `safe-browser models` | List available detection models |

## Configuration

Config file: `~/.config/safe-browser/config.yaml`

```yaml
model:
  name: protectai/deberta-v3-base-prompt-injection-v2
  device: cpu
  fail_closed: true          # Treat as suspicious if model fails

thresholds:
  block: 0.9                 # Above this → MALICIOUS
  caution: 0.5               # Above this → SUSPICIOUS

rules:
  enabled: true
  custom_patterns: []        # Add your own regex rules
```

## Detection Models

| Model | Size | Speed | Best For |
|-------|------|-------|----------|
| `protectai/deberta-v3-base-prompt-injection-v2` | ~180MB | Fast | Default, balanced |
| `meta-llama/Llama-Prompt-Guard-2-86M` | 86M params | Fastest | Real-time screening |
| `rule-based` (built-in) | — | Instant | No model download |

*Coming in Phase 2:* `perplexity-ai/browsesafe`, `openai/gpt-oss-safeguard-20b`

## Integration Examples

### With agent-browser
```bash
agent-browser snapshot | safe-browser check --json
```

### With Camoufox (via script)
```bash
safe-browser check -f /tmp/page_snapshot.html
```

### In Python
```python
from safe_browser.scanner import scan
from safe_browser.config import Config

config = Config(use_ml=False)  # or defaults
result = scan("some web content", config)
print(result.decision)   # "safe", "suspicious", "malicious"
print(result.exit_code)  # 0, 1, 2
```

## Development

```bash
git clone https://github.com/clawdbrunner/safe-browser.git
cd safe-browser
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
