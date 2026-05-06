# safe-browser

A CLI tool that screens browser content for prompt injection attacks before it reaches LLM agents.

## Features

- **Multi-model detection** — Rule-based regex + ML models (DeBERTa, Llama Prompt Guard, BrowseSafe, GPT-OSS-Safeguard)
- **Browser adapters** — Native parsing for Camoufox snapshots and agent-browser accessibility trees, with auto-detection
- **CLI-first** — Pipe content from any browser tool: `agent-browser snapshot | safe-browser check`
- **Offline-first** — All models run locally, no API calls required
- **Graceful degradation** — Falls back to rules-only if ML models are unavailable

## Quick Start

```bash
pip install safe-browser

# Check a string
safe-browser check -c "some content from the web"

# Pipe from browser tool
agent-browser snapshot | safe-browser check

# Check a file
safe-browser check -f page.html

# JSON output for scripts
safe-browser check -c "content" --json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe — no injection detected |
| 1 | Suspicious — flagged for review |
| 2 | Malicious — prompt injection detected |

## Supported Models

| Model | Size | Speed | Auth Required |
|-------|------|-------|---------------|
| `protectai/deberta-v3-base-prompt-injection` (default) | 184M | ~50ms | No |
| `meta-llama/Llama-Prompt-Guard-2-86M` | 86M | ~30ms | Yes (gated) |
| `perplexity-ai/browsesafe` | — | ~100ms | No |
| `openai/gpt-oss-safeguard-20b` | 20B | ~2s | Yes (gated) |
| `rule-based` (always available) | — | ~1ms | No |

## CLI Commands

```bash
safe-browser check [-c TEXT] [-f FILE] [--adapter ADAPTER] [--model MODEL] [--json] [--quiet]
safe-browser doctor    # Pre-flight check
safe-browser models    # List available models
```

### Options

- `--adapter / -a` — Input adapter: `auto`, `camoufox`, `agent-browser`, `raw`
- `--model / -m` — Detection model: `promptguard`, `browsesafe`, `gpt-safeguard`, `rules`
- `--json` — JSON output
- `--quiet / -q` — Exit code only
- `--no-ml` — Skip ML models, rules only

## Configuration

Config file: `~/.config/safe-browser/config.yaml`

```yaml
model:
  name: promptguard
  device: cpu
  fail_closed: true

adapter:
  default: auto

thresholds:
  block: 0.9
  caution: 0.5
```

## License

MIT

## Links

- [GitHub](https://github.com/clawdbrunner/safe-browser)
- [PyPI](https://pypi.org/project/safe-browser)
