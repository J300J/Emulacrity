from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PillarScore(BaseModel):
    score: int = Field(ge=1, le=5)
    justification: str


class ScoreBreakdown(BaseModel):
    technical_feasibility_reproducibility: PillarScore
    target_profile_relevance: PillarScore
    defensive_priority_alignment: PillarScore
    platform_tooling_compatibility: PillarScore
    supply_chain_vector: PillarScore


class EvaluationResult(BaseModel):
    actor: str
    aliases: list[str] = Field(default_factory=list)
    mode: Literal["source-driven", "discovery"]
    sources: list[str] = Field(default_factory=list)
    scores: ScoreBreakdown
    weighted_total: float = Field(ge=0, le=100)
    verdict: Literal["Recommended", "Conditional", "Not Recommended"]
    notes: str


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


def output_json_schema() -> dict:
    """JSON Schema for output_config.format, matching Emulacrity.md's Output Format."""
    schema = EvaluationResult.model_json_schema()
    return _clean_schema_node(schema)
