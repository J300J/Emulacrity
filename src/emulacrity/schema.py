from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.1"


class SourceEntry(BaseModel):
    """One source the model relied on. Code-computed fields are added after validation."""

    title: str = ""
    url: str = ""
    publisher: str = ""
    publish_date: str = ""  # YYYY-MM-DD, partial "YYYY-MM", "YYYY", or "" if unknown
    # Computed in code from url/publisher and config — never set by the model.
    on_allowlist: bool = False
    within_18_months: bool = False


class PillarScore(BaseModel):
    score: int = Field(ge=1, le=5)
    justification: str
    confidence: Literal["low", "medium", "high"] = "medium"


class ScoreBreakdown(BaseModel):
    technical_feasibility_reproducibility: PillarScore
    target_profile_relevance: PillarScore
    defensive_priority_alignment: PillarScore
    platform_tooling_compatibility: PillarScore
    supply_chain_vector: PillarScore


class ConfigSnapshot(BaseModel):
    """Snapshot of the config used for this run, for reproducibility."""

    model: str
    target_sector: str | None
    lab_supported_platforms: list[str]
    lab_internet_access: str
    pillar_weights: dict[str, float]
    attack_stix_enabled: bool


class EvaluationResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    actor: str
    aliases: list[str] = Field(default_factory=list)
    mode: Literal["source-driven", "discovery"]
    sources: list[SourceEntry] = Field(default_factory=list)
    scores: ScoreBreakdown
    weighted_total: float = Field(ge=0, le=100)
    verdict: Literal["Recommended", "Conditional", "Not Recommended"]
    # Rolled-up confidence — set in code from source analysis + pillar confidence.
    confidence: Literal["low", "medium", "high"] = "medium"
    notes: str
    config_snapshot: ConfigSnapshot | None = None


# output_config.format's JSON Schema subset doesn't support numeric/string
# range constraints — Claude's structured-output validator rejects a schema
# containing them (400: "properties maximum, minimum are not supported").
# Strip them from what's sent to the API; EvaluationResult.model_validate()
# still enforces them client-side once the response comes back.
_UNSUPPORTED_SCHEMA_KEYS = {
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
}

# Fields the model must NOT output — code computes and overwrites them after
# the response. We strip these from the schema sent to the API so the model
# doesn't waste tokens (or produce a value we'd silently ignore).
_CODE_COMPUTED_TOP_LEVEL = {"schema_version", "config_snapshot", "confidence"}
_CODE_COMPUTED_SOURCE_ENTRY = {"on_allowlist", "within_18_months"}


def _clean_schema_node(node: object) -> object:
    if isinstance(node, dict):
        cleaned = {
            key: _clean_schema_node(value)
            for key, value in node.items()
            if key not in _UNSUPPORTED_SCHEMA_KEYS
        }
        if cleaned.get("type") == "object" and "additionalProperties" not in cleaned:
            cleaned["additionalProperties"] = False
        return cleaned
    if isinstance(node, list):
        return [_clean_schema_node(item) for item in node]
    return node


def _remove_code_computed_fields(schema: dict) -> dict:
    """Strip fields code fills post-response so the model doesn't output them."""
    props = schema.get("properties", {})
    for field in _CODE_COMPUTED_TOP_LEVEL:
        props.pop(field, None)

    defs = schema.get("$defs", {})
    # Remove ConfigSnapshot definition — the model never produces it.
    defs.pop("ConfigSnapshot", None)
    # Strip code-computed fields from SourceEntry definition.
    if "SourceEntry" in defs:
        se_props = defs["SourceEntry"].get("properties", {})
        for field in _CODE_COMPUTED_SOURCE_ENTRY:
            se_props.pop(field, None)

    return schema


def output_json_schema() -> dict:
    """JSON Schema for output_config.format, matching Emulacrity.md's Output Format."""
    schema = EvaluationResult.model_json_schema()
    schema = _clean_schema_node(schema)
    schema = _remove_code_computed_fields(schema)
    return schema
