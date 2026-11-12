"""Shared fixtures for Emulacrity tests."""

from __future__ import annotations

import pytest

from emulacrity.config import Config
from emulacrity.schema import PillarScore, ScoreBreakdown


def make_scores(
    p1: int = 3,
    p2: int = 3,
    p3: int = 3,
    p4: int = 3,
    p5: int = 3,
    confidence: str = "medium",
) -> ScoreBreakdown:
    def _p(s: int) -> PillarScore:
        return PillarScore(score=s, justification="test", confidence=confidence)  # type: ignore[arg-type]

    return ScoreBreakdown(
        technical_feasibility_reproducibility=_p(p1),
        target_profile_relevance=_p(p2),
        defensive_priority_alignment=_p(p3),
        platform_tooling_compatibility=_p(p4),
        supply_chain_vector=_p(p5),
    )


@pytest.fixture()
def default_config() -> Config:
    return Config(
        target_sector="Financial Services",
        lab_supported_platforms=["windows_endpoint"],
    )
