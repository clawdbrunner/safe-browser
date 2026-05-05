"""Input adapters for reading content from various sources."""

from __future__ import annotations

import sys
from pathlib import Path


class AdapterError(Exception):
    pass


def read_stdin() -> str:
    """Read content from stdin."""
    if sys.stdin.isatty():
        raise AdapterError("No input on stdin (terminal is interactive). Pipe content or use -c/-f flags.")
    return sys.stdin.read()


def read_file(path: str) -> str:
    """Read content from a file path, with basic validation."""
    p = Path(path).resolve()

    if not p.exists():
        raise AdapterError(f"File not found: {path}")
    if not p.is_file():
        raise AdapterError(f"Not a file: {path}")

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


def get_input(content: str | None = None, file: str | None = None) -> str:
    """Resolve input from the available sources in priority order: string > file > stdin."""
    if content is not None:
        return read_string(content)
    if file is not None:
        return read_file(file)
    return read_stdin()
