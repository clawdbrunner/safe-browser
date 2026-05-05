# safe-browser

> A CLI tool that screens browser content for prompt injection attacks before it reaches LLM agents. Pluggable browser inputs, pluggable detection models.

## Problem

AI agents browsing the web are exposed to prompt injection attacks hidden in HTML — hidden divs, attributes, comments, social engineering footers, etc. Current defenses are basic pattern matching. We need ML-based detection that works as a pre-processing layer between any browser tool and any LLM agent.

## Architecture

```
Browser Tool → raw HTML/text → safe-browser → clean/sanitized content → LLM agent
                                       ↓
                              Detection Model(s)
```

**Three components, all pluggable:**

### 1. Input Adapters (browser tool → content)
Accept content from multiple sources:
- **stdin** — pipe from any CLI (`agent-browser snapshot | safe-browser check`)
- **file** — read from file path (`safe-browser check -f page.html`)
- **camoufox** — native integration with Camoufox snapshot output
- **agent-browser** — native integration with agent-browser snapshot output
- **web-fetch** — accept raw fetch output
- **string** — direct string arg (`safe-browser check -c "..."`)

### 2. Detection Models (pluggable, run in priority order)
Each model returns a verdict (SAFE / SUSPICIOUS / MALICIOUS) with confidence score and details.

Supported models (initial):
- **perplexity-ai/browsesafe** — fine-tuned prompt injection detector (HuggingFace)
- **meta-llama/Llama-Prompt-Guard-2-86M** — lightweight, fast, 86M params
- **openai/gpt-oss-safeguard-20b** — larger, more thorough
- **rule-based** — regex/pattern fallback (our current scan-content.sh logic, upgraded)

Model config via `safe-browser.yaml`:
```yaml
models:
  - name: llama-prompt-guard
    priority: 1          # run first (fastest)
    threshold: 0.7       # confidence threshold to flag
  - name: browsesafe
    priority: 2
    threshold: 0.6
  - name: gpt-oss-safeguard
    priority: 3           # run only if others are uncertain
    threshold: 0.5
  - name: rule-based
    priority: 0           # always run as baseline
```

### 3. Output
- **CLI output** — human-readable verdict + sanitized content
- **JSON output** — structured for programmatic use (`--json`)
- **exit codes** — 0=safe, 1=suspicious, 2=malicious (same as scan-content.sh convention)
- **sanitize mode** — strip/replace malicious content, return clean version (`--sanitize`)

## CLI Interface

```bash
# Check content from stdin
agent-browser snapshot | safe-browser check

# Check a file
safe-browser check -f page.html

# Check a string
safe-browser check -c "some content from the web"

# Pipe sanitized output to next tool
agent-browser snapshot | safe-browser check --sanitize | some-agent

# JSON output for scripts
safe-browser check -f page.html --json

# List available models
safe-browser models

# Run specific model only
safe-browser check --model llama-prompt-guard

# Configure
safe-browser config edit
```

## Tech Stack

- **Language:** Python (ecosystem around HuggingFace models, ONNX, etc.)
- **Package:** pip-installable, also brewable
- **Models:** Download on first use, cached locally (`~/.cache/safe-browser/models/`)
- **Config:** `~/.config/safe-browser/config.yaml`
- **Dependencies:** minimal — `transformers`, `onnxruntime` (for fast inference), `click` or `typer` for CLI

## Key Design Decisions

1. **Layered detection** — fast models first, expensive models only if needed. Short-circuit on high-confidence MALICIOUS.
2. **Offline-first** — models run locally, no API calls required (API-based models like OpenAI are optional extras).
3. **Zero-trust output** — even "safe" content gets flagged with what was checked and confidence levels.
4. **Drop-in replacement** for our current `scan-content.sh` — same exit codes, same integration points.

## MVP Scope (Phase 1)

- [ ] Project scaffold (Python, pyproject.toml, CLI with typer)
- [ ] Input adapter: stdin + file + string
- [ ] Detection model: meta-llama/Llama-Prompt-Guard-2-86M (fastest to integrate, small)
- [ ] Detection model: rule-based (port from scan-content.sh patterns)
- [ ] Output: human-readable + JSON + exit codes
- [ ] Config file support
- [ ] Tests
- [ ] README

## Phase 2

- [ ] Detection model: perplexity-ai/browsesafe
- [ ] Detection model: openai/gpt-oss-safeguard-20b
- [ ] Sanitize mode (strip malicious content, return clean)
- [ ] Input adapter: camoufox native
- [ ] Input adapter: agent-browser native
- [ ] Homebrew formula

## Publishing

- **Repo:** github.com/clawdbrunner/safe-browser
- **License:** MIT
- **PyPI:** safe-browser
- **Homebrew:** steipete/tap or clawdbrunner/tap

## Testing

- **Unit tests:** each model adapter, each input adapter
- **Integration tests:** against BrowseSafe-Bench dataset (HuggingFace)
- **Benchmark:** detection accuracy, false positive rate, latency per model

## Naming

`safe-browser` — clean, descriptive, searchable. Available on PyPI and GitHub.
