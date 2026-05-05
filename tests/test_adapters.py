"""Tests for input adapters."""

import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from safe_browser.adapters import AdapterError, get_input, read_file, read_stdin, read_string


class TestReadString:
    def test_passthrough(self):
        assert read_string("hello world") == "hello world"

    def test_empty_raises(self):
        with pytest.raises(AdapterError, match="Empty"):
            read_string("")


class TestReadFile:
    def test_reads_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("file content here")
        assert read_file(str(f)) == "file content here"

    def test_missing_file(self):
        with pytest.raises(AdapterError, match="not found"):
            read_file("/nonexistent/file.txt")

    def test_directory_not_file(self, tmp_path):
        with pytest.raises(AdapterError, match="Not a file"):
            read_file(str(tmp_path))

    def test_encoding_errors_replaced(self, tmp_path):
        f = tmp_path / "binary.txt"
        f.write_bytes(b"hello \xff\xfe world")
        result = read_file(str(f))
        assert "hello" in result
        assert "world" in result


class TestReadStdin:
    def test_reads_piped_input(self):
        fake_stdin = io.StringIO("piped content")
        fake_stdin.isatty = lambda: False
        with patch.object(sys, "stdin", fake_stdin):
            assert read_stdin() == "piped content"

    def test_tty_raises(self):
        fake_stdin = io.StringIO("")
        fake_stdin.isatty = lambda: True
        with patch.object(sys, "stdin", fake_stdin):
            with pytest.raises(AdapterError, match="stdin"):
                read_stdin()


class TestGetInput:
    def test_string_priority(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("from file")
        assert get_input(content="from string", file=str(f)) == "from string"

    def test_file_when_no_string(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("from file")
        assert get_input(file=str(f)) == "from file"

    def test_stdin_fallback(self):
        fake_stdin = io.StringIO("from stdin")
        fake_stdin.isatty = lambda: False
        with patch.object(sys, "stdin", fake_stdin):
            assert get_input() == "from stdin"
