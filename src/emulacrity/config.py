from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from emulacrity.allowlist import DEFAULT_TRUSTED_SOURCES

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 8000

DEFAULT_PILLAR_WEIGHTS: dict[str, float] = {
    "technical_feasibility_reproducibility": 0.35,
    "target_profile_relevance": 0.25,
    "defensive_priority_alignment": 0.20,
    "platform_tooling_compatibility": 0.10,
    "supply_chain_vector": 0.10,
}

VALID_PLATFORMS = {"windows_server", "windows_endpoint", "macos", "linux", "cloud"}

# Short CLI-friendly aliases for the long pillar_weights keys (--weight technical=0.4
# instead of --weight technical_feasibility_reproducibility=0.4).
PILLAR_SHORT_NAMES: dict[str, str] = {
    "technical": "technical_feasibility_reproducibility",
    "sector": "target_profile_relevance",
    "defensive": "defensive_priority_alignment",
    "platform": "platform_tooling_compatibility",
    "supply_chain": "supply_chain_vector",
}


class VerdictThresholds(BaseModel):
    """Score thresholds for compute_verdict. recommended >= conditional > Not Recommended."""

    recommended: float = 70.0
    conditional: float = 50.0


class Config(BaseModel):
    target_sector: str | None = None
    lab_supported_platforms: list[str] = Field(default_factory=list)
    lab_internet_access: Literal["connected", "air_gapped"] = "connected"
    pillar_weights: dict[str, float] = Field(
        default_factory=lambda: dict(DEFAULT_PILLAR_WEIGHTS)
    )
    defensive_priority_source: Literal["guided_prompts", "freeform", "adapter"] = (
        "guided_prompts"
    )
    attack_stix_enabled: bool = True
    trusted_source_allowlist: list[str] = Field(
        default_factory=lambda: list(DEFAULT_TRUSTED_SOURCES)
    )
    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    verdict_thresholds: VerdictThresholds = Field(default_factory=VerdictThresholds)

    @field_validator("lab_supported_platforms")
    @classmethod
    def _validate_platforms(cls, value: list[str]) -> list[str]:
        unknown = set(value) - VALID_PLATFORMS
        if unknown:
            raise ValueError(
                f"Unknown lab_supported_platforms: {sorted(unknown)}. "
                f"Valid: {sorted(VALID_PLATFORMS)}"
            )
        return value

    @field_validator("pillar_weights")
    @classmethod
    def _validate_weights(cls, value: dict[str, float]) -> dict[str, float]:
        missing = set(DEFAULT_PILLAR_WEIGHTS) - set(value)
        if missing:
            raise ValueError(f"pillar_weights is missing entries for: {sorted(missing)}")
        total = sum(value.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"pillar_weights must sum to 1.0 (100%), got {total}")
        return value

    @field_validator("trusted_source_allowlist")
    @classmethod
    def _validate_allowlist(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError(
                "trusted_source_allowlist cannot be empty — list at least one "
                "trusted vendor/org, or omit the field entirely to use the "
                "built-in default list."
            )
        return value


def resolve_pillar_key(key: str) -> str:
    """Resolve a full or short pillar_weights key. Raises ValueError if unknown."""
    key = key.strip()
    if key in DEFAULT_PILLAR_WEIGHTS:
        return key
    if key in PILLAR_SHORT_NAMES:
        return PILLAR_SHORT_NAMES[key]
    valid = sorted(set(DEFAULT_PILLAR_WEIGHTS) | set(PILLAR_SHORT_NAMES))
    raise ValueError(f"Unknown pillar '{key}'. Valid: {valid}")


def parse_weight_overrides(pairs: list[str]) -> dict[str, float]:
    """Parse repeated `--weight KEY=VALUE` flags into a pillar_weights patch.

    KEY may be a full pillar_weights key or a PILLAR_SHORT_NAMES alias.
    Only the given pillars are overridden — the rest keep whatever value
    they'd otherwise have (config file, or the built-in default).
    """
    overrides: dict[str, float] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(
                f"Invalid --weight '{pair}'. Expected KEY=VALUE, e.g. --weight technical=0.4"
            )
        raw_key, _, raw_value = pair.partition("=")
        try:
            value = float(raw_value.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid weight value in '{pair}': not a number") from exc
        overrides[resolve_pillar_key(raw_key)] = value
    return overrides


DEFAULT_CONFIG_LOCATIONS = [
    Path("emulacrity.yaml"),
    Path("emulacrity.yml"),
    Path.home() / ".config" / "emulacrity" / "config.yaml",
]


def _read_config_file(path: Path) -> dict:
    text = path.read_text()
    if path.suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}
    if path.suffix == ".json":
        return json.loads(text)
    raise ValueError(f"Unsupported config file format: {path.suffix}")


def _resolve_allowlist(raw: dict) -> None:
    """Apply trusted_source_allowlist add/remove/replace semantics in place.

    A full `trusted_source_allowlist` list short-circuits `.add`/`.remove`
    entirely and is used as-is. Otherwise `trusted_source_allowlist_add` /
    `trusted_source_allowlist_remove` apply as a diff against the built-in
    default list.
    """
    if "trusted_source_allowlist" in raw:
        raw.pop("trusted_source_allowlist_add", None)
        raw.pop("trusted_source_allowlist_remove", None)
        return

    additions = raw.pop("trusted_source_allowlist_add", None) or []
    removals = set(raw.pop("trusted_source_allowlist_remove", None) or [])
    allowlist = [s for s in DEFAULT_TRUSTED_SOURCES if s not in removals]
    for source in additions:
        if source not in allowlist:
            allowlist.append(source)
    raw["trusted_source_allowlist"] = allowlist


def load_config(
    config_path: Path | None = None, overrides: dict | None = None
) -> Config:
    """Load and merge config: built-in defaults < config file < explicit overrides.

    `overrides` may include a special `pillar_weight_overrides` key — a partial
    dict of {pillar: weight} that's merged on top of (rather than replacing)
    the base pillar_weights, so a CLI user can tweak one or two weights
    without having to restate all five.
    """
    raw: dict = {}

    path = config_path
    if path is None:
        for candidate in DEFAULT_CONFIG_LOCATIONS:
            if candidate.exists():
                path = candidate
                break

    if path is not None:
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        raw = _read_config_file(path)

    _resolve_allowlist(raw)

    if overrides:
        overrides = dict(overrides)
        weight_overrides = overrides.pop("pillar_weight_overrides", None)

        for key, value in overrides.items():
            if value is not None:
                raw[key] = value

        if weight_overrides:
            base_weights = dict(raw.get("pillar_weights") or DEFAULT_PILLAR_WEIGHTS)
            base_weights.update(weight_overrides)
            raw["pillar_weights"] = base_weights

    return Config(**raw)
