"""Input adapters for reading content from various sources."""

from __future__ import annotations

import sys
from pathlib import Path


class AdapterError(Exception):
    pass


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
