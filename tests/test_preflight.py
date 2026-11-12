"""Tests for preflight source-material validation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from emulacrity.preflight import (
    MAX_PAGES,
    MAX_REQUEST_BYTES,
    MAX_TEXT_FILE_BYTES,
    PreflightError,
    check_local_sources,
)


def _make_text_file(tmp_path: Path, size_bytes: int, name: str = "source.txt") -> Path:
    p = tmp_path / name
    p.write_bytes(b"x" * size_bytes)
    return p


# ---------------------------------------------------------------------------
# Text file size limit (gap fix)
# ---------------------------------------------------------------------------


def test_text_file_within_limit(tmp_path: Path):
    p = _make_text_file(tmp_path, MAX_TEXT_FILE_BYTES - 1)
    check_local_sources([p])  # should not raise


def test_text_file_exactly_at_limit(tmp_path: Path):
    p = _make_text_file(tmp_path, MAX_TEXT_FILE_BYTES)
    with pytest.raises(PreflightError, match="MB per-file limit"):
        check_local_sources([p])


def test_text_file_over_limit(tmp_path: Path):
    p = _make_text_file(tmp_path, MAX_TEXT_FILE_BYTES + 1024)
    with pytest.raises(PreflightError, match="MB per-file limit"):
        check_local_sources([p])


# ---------------------------------------------------------------------------
# Combined request size limit
# ---------------------------------------------------------------------------


def test_combined_size_too_large(tmp_path: Path):
    # MAX_TEXT_FILE_BYTES (2MB) << MAX_REQUEST_BYTES (32MB), so reaching the
    # combined request limit via text files alone would take 17+ files.
    # Use a mock to test the combined-size code path directly.
    p = _make_text_file(tmp_path, 1024)
    with patch("emulacrity.preflight._inspect") as mock_inspect:
        from emulacrity.preflight import _SourceInfo

        mock_inspect.return_value = _SourceInfo(path=p, raw_bytes=MAX_REQUEST_BYTES // 2 + 1)
        with pytest.raises(PreflightError, match="request limit"):
            check_local_sources([p, p])


# ---------------------------------------------------------------------------
# PDF page limit
# ---------------------------------------------------------------------------


def test_pdf_page_count_too_high(tmp_path: Path):
    p = tmp_path / "big.pdf"
    p.write_bytes(b"%PDF fake")
    with patch("emulacrity.preflight.PdfReader") as mock_reader:
        mock_reader.return_value.pages = [None] * (MAX_PAGES + 1)
        with pytest.raises(PreflightError, match="page"):
            check_local_sources([p])


def test_pdf_page_count_at_limit(tmp_path: Path):
    p = tmp_path / "ok.pdf"
    p.write_bytes(b"%PDF fake")
    with patch("emulacrity.preflight.PdfReader") as mock_reader:
        mock_reader.return_value.pages = [None] * MAX_PAGES
        check_local_sources([p])  # should not raise


def test_missing_file_raises():
    with pytest.raises(PreflightError, match="not found"):
        check_local_sources([Path("/nonexistent/source.txt")])


def test_empty_sources_ok():
    check_local_sources([])  # no-op, should not raise
