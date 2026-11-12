"""Tests for deterministic scoring helpers and evaluate_actor robustness."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from emulacrity.config import Config, VerdictThresholds
from emulacrity.schema import EvaluationResult, ScoreBreakdown
from emulacrity.scoring import compute_verdict, compute_weighted_total

from .conftest import make_scores

# ---------------------------------------------------------------------------
# compute_weighted_total
# ---------------------------------------------------------------------------


def test_weighted_total_uniform_scores():
    """All-3 scores with default weights should give 60.0."""
    config = Config()
    scores = make_scores(3, 3, 3, 3, 3)
    total = compute_weighted_total(scores, config.pillar_weights)
    assert total == pytest.approx(60.0, abs=0.01)


def test_weighted_total_all_max():
    """All-5 scores should give 100.0 when weights sum to 1.0."""
    config = Config()
    scores = make_scores(5, 5, 5, 5, 5)
    assert compute_weighted_total(scores, config.pillar_weights) == pytest.approx(100.0, abs=0.01)


def test_weighted_total_all_min():
    """All-1 scores should give 20.0 (1/5 * 1.0 * 100)."""
    config = Config()
    scores = make_scores(1, 1, 1, 1, 1)
    assert compute_weighted_total(scores, config.pillar_weights) == pytest.approx(20.0, abs=0.01)


def test_weighted_total_known_values():
    """Explicit calculation: p1=4(35%), p2=5(25%), p3=3(20%), p4=2(10%), p5=1(10%)."""
    weights = {
        "technical_feasibility_reproducibility": 0.35,
        "target_profile_relevance": 0.25,
        "defensive_priority_alignment": 0.20,
        "platform_tooling_compatibility": 0.10,
        "supply_chain_vector": 0.10,
    }
    scores = make_scores(4, 5, 3, 2, 1)
    expected = (4 / 5) * 0.35 * 100 + (5 / 5) * 0.25 * 100 + (3 / 5) * 0.20 * 100 + (2 / 5) * 0.10 * 100 + (1 / 5) * 0.10 * 100
    assert compute_weighted_total(scores, weights) == pytest.approx(expected, abs=0.01)


# ---------------------------------------------------------------------------
# compute_verdict
# ---------------------------------------------------------------------------


def test_verdict_recommended():
    t = VerdictThresholds()
    assert compute_verdict(75.0, 3, t) == "Recommended"


def test_verdict_conditional():
    t = VerdictThresholds()
    assert compute_verdict(60.0, 3, t) == "Conditional"


def test_verdict_not_recommended_low_total():
    t = VerdictThresholds()
    assert compute_verdict(40.0, 3, t) == "Not Recommended"


def test_verdict_pillar1_gate():
    """Pillar 1 = 1 forces Not Recommended regardless of total."""
    t = VerdictThresholds()
    assert compute_verdict(95.0, 1, t) == "Not Recommended"


def test_verdict_boundary_recommended():
    t = VerdictThresholds(recommended=70.0, conditional=50.0)
    assert compute_verdict(70.0, 3, t) == "Recommended"
    assert compute_verdict(69.9, 3, t) == "Conditional"


def test_verdict_boundary_conditional():
    t = VerdictThresholds(recommended=70.0, conditional=50.0)
    assert compute_verdict(50.0, 3, t) == "Conditional"
    assert compute_verdict(49.9, 3, t) == "Not Recommended"


def test_verdict_custom_thresholds():
    t = VerdictThresholds(recommended=80.0, conditional=60.0)
    assert compute_verdict(79.9, 3, t) == "Conditional"
    assert compute_verdict(80.0, 3, t) == "Recommended"


# ---------------------------------------------------------------------------
# evaluate_actor with mocked client
# ---------------------------------------------------------------------------


def _make_mock_response(
    stop_reason: str = "end_turn",
    text: str | None = None,
    result_obj: EvaluationResult | None = None,
) -> MagicMock:
    if result_obj is not None:
        text = result_obj.model_dump_json()
    block = MagicMock()
    block.type = "text"
    block.text = text or "{}"
    resp = MagicMock()
    resp.stop_reason = stop_reason
    resp.content = [block]
    resp.stop_details = None
    return resp


def _minimal_result(scores: ScoreBreakdown | None = None) -> EvaluationResult:
    s = scores or make_scores()
    return EvaluationResult(
        actor="TestActor",
        mode="discovery",
        scores=s,
        weighted_total=60.0,
        verdict="Conditional",
        notes="",
    )


def test_evaluate_actor_pause_turn_then_end(default_config: Config):
    """pause_turn response should trigger a retry."""
    from emulacrity.scoring import evaluate_actor

    final = _minimal_result()
    pause_resp = MagicMock()
    pause_resp.stop_reason = "pause_turn"
    pause_resp.content = []

    end_resp = _make_mock_response(result_obj=final)

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [pause_resp, end_resp]

    with patch("emulacrity.scoring.lookup_group", return_value=None):
        result = evaluate_actor("TestActor", default_config, client=mock_client)

    assert mock_client.messages.create.call_count == 2
    assert result.actor == "TestActor"


def test_evaluate_actor_pause_turn_cap(default_config: Config):
    """Exceeding the pause_turn iteration cap should raise RuntimeError."""
    from emulacrity.scoring import _PAUSE_TURN_MAX_ITERATIONS, evaluate_actor

    pause_resp = MagicMock()
    pause_resp.stop_reason = "pause_turn"
    pause_resp.content = []

    mock_client = MagicMock()
    mock_client.messages.create.return_value = pause_resp

    with patch("emulacrity.scoring.lookup_group", return_value=None), pytest.raises(
        RuntimeError, match="pause_turn iteration cap"
    ):
        evaluate_actor("TestActor", default_config, client=mock_client)

    # Initial call + (cap-1) resume calls before the exception fires = cap total
    assert mock_client.messages.create.call_count == _PAUSE_TURN_MAX_ITERATIONS


def test_evaluate_actor_refusal(default_config: Config):
    """stop_reason=refusal should raise RuntimeError."""
    from emulacrity.scoring import evaluate_actor

    resp = MagicMock()
    resp.stop_reason = "refusal"
    resp.content = []
    resp.stop_details = "policy violation"

    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    with patch("emulacrity.scoring.lookup_group", return_value=None), pytest.raises(
        RuntimeError, match="declined"
    ):
        evaluate_actor("TestActor", default_config, client=mock_client)


def test_evaluate_actor_no_text_block(default_config: Config):
    """No text block in response should raise RuntimeError."""
    from emulacrity.scoring import evaluate_actor

    resp = MagicMock()
    resp.stop_reason = "end_turn"
    resp.content = []  # no text blocks

    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    with patch("emulacrity.scoring.lookup_group", return_value=None), pytest.raises(
        RuntimeError, match="No text block"
    ):
        evaluate_actor("TestActor", default_config, client=mock_client)


def test_evaluate_actor_max_tokens(default_config: Config):
    """stop_reason=max_tokens should raise RuntimeError."""
    from emulacrity.scoring import evaluate_actor

    resp = MagicMock()
    resp.stop_reason = "max_tokens"
    resp.content = []

    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    with patch("emulacrity.scoring.lookup_group", return_value=None), pytest.raises(
        RuntimeError, match="token limit"
    ):
        evaluate_actor("TestActor", default_config, client=mock_client)


def test_evaluate_actor_malformed_json_retries(default_config: Config):
    """Malformed JSON triggers one retry; raises on second failure."""
    from emulacrity.scoring import evaluate_actor

    bad_block = MagicMock()
    bad_block.type = "text"
    bad_block.text = "not valid json {"

    bad_resp = MagicMock()
    bad_resp.stop_reason = "end_turn"
    bad_resp.content = [bad_block]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = bad_resp

    with patch("emulacrity.scoring.lookup_group", return_value=None), pytest.raises(
        RuntimeError, match="Could not parse"
    ):
        evaluate_actor("TestActor", default_config, client=mock_client)

    assert mock_client.messages.create.call_count == 2


def test_evaluate_actor_overwrites_wrong_weighted_total(default_config: Config):
    """Model's wrong weighted_total is overwritten by code-computed value."""
    from emulacrity.scoring import evaluate_actor

    scores = make_scores(3, 3, 3, 3, 3)
    result_obj = EvaluationResult(
        actor="TestActor",
        mode="discovery",
        scores=scores,
        weighted_total=99.0,  # deliberately wrong
        verdict="Conditional",
        notes="",
    )
    resp = _make_mock_response(result_obj=result_obj)
    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    with patch("emulacrity.scoring.lookup_group", return_value=None):
        result = evaluate_actor("TestActor", default_config, client=mock_client)

    assert result.weighted_total == pytest.approx(60.0, abs=0.1)
    assert "Auto:" in result.notes


def test_evaluate_actor_pillar1_gate_overrides_verdict(default_config: Config):
    """Pillar 1 = 1 must force Not Recommended even if model says Recommended."""
    from emulacrity.scoring import evaluate_actor

    scores = make_scores(p1=1, p2=5, p3=5, p4=5, p5=5)
    result_obj = EvaluationResult(
        actor="TestActor",
        mode="discovery",
        scores=scores,
        weighted_total=85.0,
        verdict="Recommended",  # model got it wrong
        notes="",
    )
    resp = _make_mock_response(result_obj=result_obj)
    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    with patch("emulacrity.scoring.lookup_group", return_value=None):
        result = evaluate_actor("TestActor", default_config, client=mock_client)

    assert result.verdict == "Not Recommended"
    assert "Auto:" in result.notes
