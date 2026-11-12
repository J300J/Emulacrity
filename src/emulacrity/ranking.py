"""Multi-actor ranking logic for `emulacrity rank`."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import anthropic

from emulacrity.config import Config
from emulacrity.defensive import load_adapter_context
from emulacrity.schema import EvaluationResult
from emulacrity.scoring import evaluate_actor

NEAR_TIE_THRESHOLD = 3.0

PILLAR_SHORT_LABELS: dict[str, str] = {
    "technical_feasibility_reproducibility": "P1",
    "target_profile_relevance": "P2",
    "defensive_priority_alignment": "P3",
    "platform_tooling_compatibility": "P4",
    "supply_chain_vector": "P5",
}


def sort_results(results: list[EvaluationResult]) -> list[EvaluationResult]:
    """Sort by weighted_total descending; Pillar-1-gated actors sink to bottom."""
    gated = [r for r in results if r.scores.technical_feasibility_reproducibility.score == 1]
    ungated = [r for r in results if r.scores.technical_feasibility_reproducibility.score != 1]
    ungated.sort(key=lambda r: r.weighted_total, reverse=True)
    gated.sort(key=lambda r: r.weighted_total, reverse=True)
    return ungated + gated


def compute_ranking_deltas(
    results: list[EvaluationResult], weights: dict[str, float]
) -> list[dict]:
    """For each adjacent ranked pair, compute the per-pillar point contribution.

    Returns a list of dicts (one per gap), each with:
      gap, pillar_deltas (per-pillar point difference), primary_driver.
    Index i corresponds to the gap between results[i] and results[i+1].
    """
    deltas = []
    for i in range(len(results) - 1):
        higher = results[i]
        lower = results[i + 1]
        gap = round(higher.weighted_total - lower.weighted_total, 1)
        pillar_contribs: dict[str, float] = {}
        for pillar_key, weight in weights.items():
            score_h = getattr(higher.scores, pillar_key).score
            score_l = getattr(lower.scores, pillar_key).score
            pillar_contribs[pillar_key] = round((score_h - score_l) / 5 * weight * 100, 1)
        primary = max(pillar_contribs, key=lambda k: abs(pillar_contribs[k]))
        deltas.append(
            {
                "gap": gap,
                "pillar_deltas": pillar_contribs,
                "primary_driver": primary,
            }
        )
    return deltas


def rank_actors(
    actors: list[str],
    config: Config,
    *,
    defensive_adapter: Path | None = None,
    concurrency: int = 3,
) -> tuple[list[EvaluationResult], list[tuple[str, str]]]:
    """Score actors concurrently; return (results_list, errors_list).

    One failure does not kill the batch. errors_list is a list of
    (actor_name, error_message) tuples.
    """
    client = anthropic.Anthropic()
    results: list[EvaluationResult] = []
    errors: list[tuple[str, str]] = []

    def _score_one(actor: str) -> EvaluationResult:
        defensive_context = None
        if defensive_adapter is not None:
            defensive_context = load_adapter_context(defensive_adapter, actor)
        return evaluate_actor(
            actor,
            config,
            defensive_priority_context=defensive_context,
            client=client,
        )

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_actor = {executor.submit(_score_one, a): a for a in actors}
        for future in as_completed(future_to_actor):
            actor = future_to_actor[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                errors.append((actor, str(exc)))

    return results, errors


def build_rank_output(
    results: list[EvaluationResult],
    errors: list[tuple[str, str]],
    config: Config,
) -> dict:
    """Build the combined JSON output for `emulacrity rank`."""
    sorted_results = sort_results(results)
    deltas = compute_ranking_deltas(sorted_results, config.pillar_weights)

    ranked = []
    for i, result in enumerate(sorted_results):
        gated = result.scores.technical_feasibility_reproducibility.score == 1
        near_tie = i < len(sorted_results) - 1 and (
            sorted_results[i].weighted_total - sorted_results[i + 1].weighted_total
            <= NEAR_TIE_THRESHOLD
        )
        entry: dict = {
            "rank": i + 1,
            "gated": gated,
            "near_tie_with_next": near_tie,
            "gap_from_previous": deltas[i - 1]["gap"] if i > 0 else None,
            "pillar_deltas_from_previous": (
                {
                    PILLAR_SHORT_LABELS.get(k, k): v
                    for k, v in deltas[i - 1]["pillar_deltas"].items()
                }
                if i > 0
                else None
            ),
            "primary_driver_from_previous": (
                PILLAR_SHORT_LABELS.get(deltas[i - 1]["primary_driver"], "")
                if i > 0
                else None
            ),
            "evaluation": result.model_dump(),
        }
        ranked.append(entry)

    return {
        "schema_version": "1.1",
        "actors": ranked,
        "errors": [{"actor": a, "error": e} for a, e in errors],
    }
