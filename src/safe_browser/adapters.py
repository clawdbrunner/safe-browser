"""Input adapters for reading content from various sources."""

from __future__ import annotations

import json
import sys
from pathlib import Path


class AdapterError(Exception):
    pass


# --- Browser format adapters ---


def parse_camoufox_snapshot(data: dict) -> str:
    """Extract text from camoufox snapshot JSON.

    Format: { "snapshot": { "documents": [{ "nodes": [{ "type", "name", "value", "children" }] }] } }
    Walk all nodes recursively, extract text from name/value/children.
    Include hidden=True nodes (they may contain injection attempts).
    """
    parts: list[str] = []

    def _walk(node):
        if isinstance(node, dict):
            for key in ("name", "value"):
                val = node.get(key)
                if val and isinstance(val, str):
                    parts.append(val)
            for child in node.get("children", []):
                _walk(child)
            for child in node.get("nodes", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

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


def parse_agent_browser_tree(data: dict) -> str:
    """Extract text from agent-browser accessibility tree.

    Format: { "role": "WebArea", "name": "Page Title", "children": [...] }
    Walk all nodes, extract role + name text.
    """
    parts: list[str] = []

    def _walk(node):
        if isinstance(node, dict):
            role = node.get("role", "")
            name = node.get("name", "")
            if name:
                parts.append(name)
            elif role and role not in ("none", "generic"):
                parts.append(role)
            for child in node.get("children", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return " ".join(parts)


def detect_adapter(content: str) -> str:
    """Auto-detect content format.

    - If content parses as JSON with 'snapshot' key → 'camoufox'
    - If content parses as JSON with 'role' key → 'agent_browser'
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
        pass
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
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            raise AdapterError(f"Agent-browser adapter: invalid JSON: {e}")
        return parse_agent_browser_tree(data)
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
