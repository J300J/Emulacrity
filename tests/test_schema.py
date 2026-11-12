"""Tests for schema cleaning and output_json_schema."""

from __future__ import annotations

from emulacrity.schema import _clean_schema_node, output_json_schema


def test_clean_schema_strips_minimum_maximum():
    node = {"type": "integer", "minimum": 1, "maximum": 5}
    result = _clean_schema_node(node)
    assert "minimum" not in result
    assert "maximum" not in result
    assert result["type"] == "integer"


def test_clean_schema_strips_string_length_constraints():
    node = {"type": "string", "minLength": 1, "maxLength": 100}
    result = _clean_schema_node(node)
    assert "minLength" not in result
    assert "maxLength" not in result


def test_clean_schema_adds_additional_properties_false():
    node = {"type": "object", "properties": {"x": {"type": "string"}}}
    result = _clean_schema_node(node)
    assert result.get("additionalProperties") is False


def test_clean_schema_respects_existing_additional_properties():
    node = {"type": "object", "additionalProperties": True}
    result = _clean_schema_node(node)
    assert result.get("additionalProperties") is True


def test_clean_schema_nested():
    node = {
        "type": "object",
        "properties": {
            "score": {"type": "integer", "minimum": 1, "maximum": 5},
        },
    }
    result = _clean_schema_node(node)
    score_prop = result["properties"]["score"]
    assert "minimum" not in score_prop
    assert "maximum" not in score_prop


def test_output_json_schema_no_code_computed_top_level():
    schema = output_json_schema()
    props = schema.get("properties", {})
    assert "schema_version" not in props
    assert "config_snapshot" not in props
    # top-level 'confidence' (rolled-up) should not be present
    assert "confidence" not in props


def test_output_json_schema_source_entry_no_computed_fields():
    schema = output_json_schema()
    defs = schema.get("$defs", {})
    assert "SourceEntry" in defs
    se_props = defs["SourceEntry"].get("properties", {})
    assert "on_allowlist" not in se_props
    assert "within_18_months" not in se_props


def test_output_json_schema_source_entry_has_model_fields():
    schema = output_json_schema()
    defs = schema.get("$defs", {})
    se_props = defs["SourceEntry"].get("properties", {})
    for field in ("title", "url", "publisher", "publish_date"):
        assert field in se_props, f"SourceEntry missing field: {field}"


def test_output_json_schema_pillar_confidence_present():
    """PillarScore.confidence is set by the model and must remain in the schema."""
    schema = output_json_schema()
    defs = schema.get("$defs", {})
    assert "PillarScore" in defs
    ps_props = defs["PillarScore"].get("properties", {})
    assert "confidence" in ps_props
