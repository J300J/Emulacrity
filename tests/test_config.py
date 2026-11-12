"""Tests for config loading, weight overrides, and resolution order."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from emulacrity.config import (
    DEFAULT_PILLAR_WEIGHTS,
    Config,
    VerdictThresholds,
    load_config,
    parse_weight_overrides,
)

# ---------------------------------------------------------------------------
# parse_weight_overrides
# ---------------------------------------------------------------------------


def test_parse_weight_overrides_full_key():
    result = parse_weight_overrides(["technical_feasibility_reproducibility=0.4"])
    assert result["technical_feasibility_reproducibility"] == pytest.approx(0.4)


def test_parse_weight_overrides_short_key():
    result = parse_weight_overrides(["technical=0.4"])
    assert result["technical_feasibility_reproducibility"] == pytest.approx(0.4)


def test_parse_weight_overrides_multiple():
    result = parse_weight_overrides(["technical=0.4", "sector=0.2"])
    assert result["technical_feasibility_reproducibility"] == pytest.approx(0.4)
    assert result["target_profile_relevance"] == pytest.approx(0.2)


def test_parse_weight_overrides_bad_format():
    with pytest.raises(ValueError, match="Expected KEY=VALUE"):
        parse_weight_overrides(["technical0.4"])


def test_parse_weight_overrides_bad_value():
    with pytest.raises(ValueError, match="not a number"):
        parse_weight_overrides(["technical=abc"])


def test_parse_weight_overrides_unknown_key():
    with pytest.raises(ValueError, match="Unknown pillar"):
        parse_weight_overrides(["unknown_pillar=0.4"])


# ---------------------------------------------------------------------------
# Config weight validation
# ---------------------------------------------------------------------------


def test_config_weights_must_sum_to_1():
    bad_weights = dict(DEFAULT_PILLAR_WEIGHTS)
    bad_weights["technical_feasibility_reproducibility"] = 0.99  # sum >> 1
    with pytest.raises(ValueError, match="sum to 1.0"):
        Config(pillar_weights=bad_weights)


def test_config_weights_missing_pillar():
    with pytest.raises(ValueError, match="missing entries"):
        Config(pillar_weights={"technical_feasibility_reproducibility": 1.0})


# ---------------------------------------------------------------------------
# Config resolution order
# ---------------------------------------------------------------------------


def test_load_config_defaults():
    cfg = load_config()
    assert cfg.target_sector is None
    assert cfg.lab_internet_access == "connected"
    assert cfg.pillar_weights == DEFAULT_PILLAR_WEIGHTS


def test_load_config_from_file(tmp_path: Path):
    cfg_file = tmp_path / "emulacrity.yaml"
    cfg_file.write_text(
        yaml.safe_dump({"target_sector": "Healthcare", "lab_internet_access": "air_gapped"})
    )
    cfg = load_config(config_path=cfg_file)
    assert cfg.target_sector == "Healthcare"
    assert cfg.lab_internet_access == "air_gapped"


def test_load_config_overrides_take_precedence(tmp_path: Path):
    cfg_file = tmp_path / "emulacrity.yaml"
    cfg_file.write_text(yaml.safe_dump({"target_sector": "Healthcare"}))
    cfg = load_config(config_path=cfg_file, overrides={"target_sector": "Energy"})
    assert cfg.target_sector == "Energy"


def test_load_config_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config(config_path=Path("/nonexistent/emulacrity.yaml"))


def test_load_config_weight_overrides_merge(tmp_path: Path):
    """Partial weight override via pillar_weight_overrides merges, doesn't replace."""
    cfg_file = tmp_path / "emulacrity.yaml"
    cfg_file.write_text(yaml.safe_dump({}))
    overrides = {
        "pillar_weight_overrides": {
            "technical_feasibility_reproducibility": 0.40,
            "supply_chain_vector": 0.05,
        }
    }
    cfg = load_config(config_path=cfg_file, overrides=overrides)
    assert cfg.pillar_weights["technical_feasibility_reproducibility"] == pytest.approx(0.40)
    assert cfg.pillar_weights["supply_chain_vector"] == pytest.approx(0.05)
    total = sum(cfg.pillar_weights.values())
    assert total == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# VerdictThresholds
# ---------------------------------------------------------------------------


def test_verdict_thresholds_defaults():
    t = VerdictThresholds()
    assert t.recommended == 70.0
    assert t.conditional == 50.0


def test_config_has_model_and_max_tokens():
    cfg = Config()
    assert isinstance(cfg.model, str)
    assert cfg.max_tokens > 0


def test_config_model_overridable():
    cfg = Config(model="claude-opus-5-5")
    assert cfg.model == "claude-opus-5-5"
