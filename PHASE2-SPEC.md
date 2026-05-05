# safe-browser Phase 2 Spec

## Goal
Add native browser adapters (Camoufox, agent-browser) and additional detection models (perplexity-ai/browsesafe, openai/gpt-oss-safeguard-20b).

---

## 1. Browser Adapters

### Camoufox Adapter
Camoufox is our primary browser automation tool. It outputs accessibility snapshots with element refs (e1, e2, etc.) plus visible text.

**Integration:**
```bash
# Pipe camoufox snapshot output directly
camofox_snapshot → safe-browser check --adapter camoufox

# Or auto-detect camoufox JSON format
safe-browser check -f snapshot.json --adapter camoufox
```

**What to extract:**
- The `camofox_snapshot` response includes element text content and metadata
- Adapter should parse the snapshot format and extract all visible text + element attributes (hidden text in `aria-hidden`, `style="display:none"`, etc. is especially relevant for injection detection)

**Reference:** Camoufox snapshots are structured JSON with element refs, text content, and accessibility tree. The adapter needs to handle this format and extract the textual content for scanning.

### agent-browser Adapter
agent-browser is a fast Rust-based browser tool that outputs accessibility trees with refs.

**Integration:**
```bash
# Pipe agent-browser snapshot output
agent-browser snapshot | safe-browser check --adapter agent-browser

# Or from file
safe-browser check -f snapshot.txt --adapter agent-browser
```

**What to extract:**
- agent-browser outputs an accessibility tree in a specific text format
- Parse out the text content from the tree for scanning

### Implementation Notes
- Both adapters should be added to `adapters.py`
- Auto-detection: if no `--adapter` flag, try to detect format from content (JSON with camoufox keys → camoufox, text with `[ref]` patterns → agent-browser, fallback to raw text)
- Each adapter should extract the maximum text content including hidden/invisible elements (those are the attack vectors)

---

## 2. Detection Models

### perplexity-ai/browsesafe
- **Source:** HuggingFace (perplexity-ai/browsesafe)
- **Type:** Fine-tuned prompt injection detector
- **Purpose:** Specialized for detecting injection in web content
- **Integration:** Use `transformers` library, download and cache model on first use
- **Threshold:** Default 0.6 confidence for flagging

### openai/gpt-oss-safeguard-20b
- **Source:** HuggingFace (openai/gpt-oss-safeguard-20b)  
- **Type:** Larger safety classifier, 20B params
- **Purpose:** More thorough detection, catches subtle social engineering
- **Integration:** Use `transformers` + `onnxruntime` for efficient inference
- **Threshold:** Default 0.5 confidence for flagging
- **Note:** This is a larger model — may need ONNX quantization for reasonable latency. Consider making it optional / only run if smaller models return SUSPICIOUS.

### Model Priority
Models run in priority order (fastest first). Short-circuit on high-confidence MALICIOUS:
1. rule-based (existing, instant)
2. meta-llama/Llama-Prompt-Guard-2-86M (existing, fast)
3. perplexity-ai/browsesafe (new, medium speed)
4. openai/gpt-oss-safeguard-20b (new, slow — only if others uncertain)

### Config
Update config schema to support new models with same format:
```yaml
models:
  - name: rule-based
    priority: 0
  - name: llama-prompt-guard
    priority: 1
    threshold: 0.7
  - name: browsesafe
    priority: 2
    threshold: 0.6
  - name: gpt-oss-safeguard
    priority: 3
    threshold: 0.5
```

---

## 3. CLI Changes

```bash
# New --adapter flag
safe-browser check --adapter camoufox -f snapshot.json
safe-browser check --adapter agent-browser -f snapshot.txt

# New --model flag (run specific model)
safe-browser check --model browsesafe
safe-browser check --model gpt-oss-safeguard

# Auto-detect adapter from content
safe-browser check -f snapshot.json  # detects camoufox JSON

# List models (updated to show new ones)
safe-browser models
```

---

## 4. Testing

- Unit tests for each new adapter (camoufox JSON parsing, agent-browser text parsing)
- Unit tests for each new model (mock inference, verify verdict format)
- Integration test: end-to-end with sample snapshots containing injection payloads
- Test that auto-detection correctly identifies adapter format

---

## 5. Files to Modify/Create

- `src/safe_browser/adapters.py` — add CamoufoxAdapter, AgentBrowserAdapter, auto-detect logic
- `src/safe_browser/models.py` — add BrowseSafeModel, GptOssSafeguardModel
- `src/safe_browser/cli.py` — add `--adapter` flag, update `--model` to include new options
- `src/safe_browser/config.py` — update config schema for new models
- `tests/test_adapters.py` — tests for new adapters
- `tests/test_models.py` — tests for new models

---

## 6. Notes

- Remove sanitize mode from the spec/roadmap — not doing it
- Models download on first use, cached at `~/.cache/safe-browser/models/`
- Large models (gpt-oss-safeguard) should be optional — if download fails or takes too long, skip gracefully
- Keep offline-first: all models run locally, no API calls
