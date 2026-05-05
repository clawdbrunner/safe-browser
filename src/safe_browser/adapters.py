"""Input adapters for reading content from various sources."""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class AdapterError(Exception):
    pass


MAX_DEPTH = 50

# --- Browser format adapters ---


def _is_hidden_node(node: dict) -> bool:
    """Check if a node has aria-hidden or hidden CSS styles."""
    if node.get("aria-hidden") == "true" or node.get("aria-hidden") is True:
        return True
    style = node.get("style", "")
    if isinstance(style, str):
        normalized = style.replace(" ", "").lower()
        if "display:none" in normalized or "visibility:hidden" in normalized:
            return True
    return False


def parse_camoufox_snapshot(data: dict, max_depth: int = MAX_DEPTH) -> str:
    """Extract text from camoufox snapshot JSON.

    Format: { "snapshot": { "documents": [{ "nodes": [{ "type", "name", "value", "children" }] }] } }
    Walk all nodes recursively, extract text from name/value/children.
    Include hidden=True nodes (they may contain injection attempts).
    Nodes with aria-hidden="true" or display:none/visibility:hidden get [HIDDEN] prefix.
    """
    parts: list[str] = []

    def _walk(node, depth=0):
        if depth > max_depth:
            logger.warning("Camoufox tree depth exceeded %d, stopping recursion", max_depth)
            return
        if isinstance(node, dict):
            hidden = _is_hidden_node(node)
            for key in ("name", "value"):
                val = node.get(key)
                if val and isinstance(val, str):
                    parts.append(f"[HIDDEN] {val}" if hidden else val)
            for child in node.get("children", []):
                _walk(child, depth + 1)
            for child in node.get("nodes", []):
                _walk(child, depth + 1)
        elif isinstance(node, list):
            for item in node:
                _walk(item, depth + 1)

    snapshot = data.get("snapshot", data)
    documents = snapshot.get("documents", [])
    if isinstance(documents, list):
        for doc in documents:
            _walk(doc)
    else:
        _walk(snapshot)

    # If nothing found in documents, walk the whole structure
    if not parts:
        _walk(data)

    return " ".join(parts)


def parse_agent_browser_tree(data: dict, max_depth: int = MAX_DEPTH) -> str:
    """Extract text from agent-browser accessibility tree (JSON format).

    Format: { "role": "WebArea", "name": "Page Title", "children": [...] }
    Walk all nodes, extract role + name text.
    """
    parts: list[str] = []

    def _walk(node, depth=0):
        if depth > max_depth:
            logger.warning("Agent-browser tree depth exceeded %d, stopping recursion", max_depth)
            return
        if isinstance(node, dict):
            role = node.get("role", "")
            name = node.get("name", "")
            if name:
                parts.append(name)
            elif role and role not in ("none", "generic"):
                parts.append(role)
            for child in node.get("children", []):
                _walk(child, depth + 1)
        elif isinstance(node, list):
            for item in node:
                _walk(item, depth + 1)

    _walk(data)
    return " ".join(parts)


_AGENT_BROWSER_LINE_RE = re.compile(r'^\s*\[(\w+)\]\s*(?:"([^"]*)")?')


def parse_agent_browser_text(content: str) -> str:
    """Parse agent-browser TEXT format accessibility tree.

    Format:
        [WebArea] "Page Title"
          [heading] "Welcome"
            [link] "Click here" ref=e1
          [textbox] "Search" ref=e2
            "current text"
          [button] "Submit" ref=e3

    Extracts role, name, ref identifiers, and plain text lines.
    """
    parts: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = _AGENT_BROWSER_LINE_RE.match(line)
        if m:
            role = m.group(1)
            name = m.group(2)
            if name:
                parts.append(name)
            elif role:
                parts.append(role)
            # Extract ref= identifier
            ref_match = re.search(r'ref=(\S+)', line)
            if ref_match:
                parts.append(ref_match.group(1))
        else:
            # Plain text line (possibly quoted)
            text = stripped.strip('"')
            if text:
                parts.append(text)
    return "\n".join(parts)


def _has_agent_browser_text_lines(content: str) -> bool:
    """Check if content looks like agent-browser text format."""
    count = 0
    for line in content.splitlines():
        if _AGENT_BROWSER_LINE_RE.match(line):
            count += 1
            if count >= 2:
                return True
    return False


def detect_adapter(content: str) -> str:
    """Auto-detect content format.

    - If content parses as JSON with 'snapshot' key → 'camoufox'
    - If content parses as JSON with 'role' key → 'agent_browser'
    - If content has lines matching [role] pattern (non-JSON) → 'agent_browser'
    - Otherwise → 'raw' (plain text)
    """
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if "snapshot" in data:
                return "camoufox"
            if "role" in data:
                return "agent_browser"
    except (json.JSONDecodeError, ValueError):
        # Not JSON — check for text-format agent-browser
        if _has_agent_browser_text_lines(content):
            return "agent_browser"
    return "raw"


def adapt_input(content: str, adapter: str = "auto") -> str:
    """Parse content through the appropriate browser adapter.

    Args:
        content: Raw input text (may be JSON or plain text)
        adapter: "auto", "camoufox", "agent_browser", or "raw"

    Returns:
        Extracted text content ready for scanning.
    """
    if adapter == "auto":
        adapter = detect_adapter(content)

    if adapter == "camoufox":
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            raise AdapterError(f"Camoufox adapter: invalid JSON: {e}")
        return parse_camoufox_snapshot(data)
    elif adapter == "agent_browser":
        # Try JSON first, fall back to text format
        try:
            data = json.loads(content)
            return parse_agent_browser_tree(data)
        except (json.JSONDecodeError, ValueError):
            return parse_agent_browser_text(content)
    else:
        return content


def read_stdin(max_bytes: int = 10 * 1024 * 1024) -> str:
    """Read content from stdin with size limit."""
    if sys.stdin.isatty():
        raise AdapterError("No input on stdin (terminal is interactive). Pipe content or use -c/-f flags.")
    data = sys.stdin.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise AdapterError(f"Input too large: exceeds {max_bytes} bytes")
    return data


def read_file(path: str, max_bytes: int = 10 * 1024 * 1024) -> str:
    """Read content from a file path, with basic validation and size limit."""
    p = Path(path).resolve()

    if not p.exists():
        raise AdapterError(f"File not found: {path}")
    if not p.is_file():
        raise AdapterError(f"Not a file: {path}")

    size = p.stat().st_size
    if size > max_bytes:
        raise AdapterError(f"File too large: {size} bytes (limit: {max_bytes})")

    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        raise AdapterError(f"Permission denied: {path}")
    except OSError as e:
        raise AdapterError(f"Failed to read {path}: {e}")


def read_string(content: str) -> str:
    """Pass through a string (minimal validation)."""
    if not content:
        raise AdapterError("Empty content string")
    return content


def get_input(content: str | None = None, file: str | None = None, max_bytes: int = 10 * 1024 * 1024) -> str:
    """Resolve input from the available sources in priority order: string > file > stdin."""
    if content is not None:
        return read_string(content)
    if file is not None:
        return read_file(file, max_bytes=max_bytes)
    return read_stdin(max_bytes=max_bytes)
