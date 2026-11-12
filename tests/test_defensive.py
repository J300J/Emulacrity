"""Tests for defensive.py adapter JSON parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from emulacrity.defensive import load_adapter_context


def _write_adapter(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "adapter.json"
    p.write_text(json.dumps(entries))
    return p


def test_adapter_exact_match(tmp_path: Path):
    p = _write_adapter(tmp_path, [{"actor": "APT34", "alert_count_90d": 3, "active_hunt": True}])
    result = load_adapter_context(p, "APT34")
    assert result is not None
    assert "alert_count_90d" in result
    assert "3" in result


def test_adapter_case_insensitive_match(tmp_path: Path):
    p = _write_adapter(tmp_path, [{"actor": "apt34", "notes": "tracked"}])
    result = load_adapter_context(p, "APT34")
    assert result is not None


def test_adapter_no_match_returns_none(tmp_path: Path, capsys):
    p = _write_adapter(tmp_path, [{"actor": "FIN7", "notes": "tracked"}])
    result = load_adapter_context(p, "APT34")
    assert result is None


def test_adapter_missing_file():
    with pytest.raises(FileNotFoundError):
        load_adapter_context(Path("/nonexistent/adapter.json"), "APT34")


def test_adapter_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json {")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_adapter_context(p, "APT34")


def test_adapter_not_a_list(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"actor": "APT34"}))
    with pytest.raises(ValueError, match="JSON array"):
        load_adapter_context(p, "APT34")


def test_adapter_actor_key_excluded_from_output(tmp_path: Path):
    p = _write_adapter(tmp_path, [{"actor": "APT34", "notes": "important"}])
    result = load_adapter_context(p, "APT34")
    assert result is not None
    assert "actor" not in result
    assert "notes" in result
