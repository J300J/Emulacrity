from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Literal

import anthropic

from emulacrity.allowlist import is_on_allowlist
from emulacrity.attack_stix import format_group_context, lookup_group
from emulacrity.config import Config, VerdictThresholds
from emulacrity.preflight import check_local_sources
from emulacrity.prompts import build_system_prompt, build_user_message
from emulacrity.schema import (
    ConfigSnapshot,
    EvaluationResult,
    PillarScore,
    ScoreBreakdown,
    SourceEntry,
    output_json_schema,
)

logger = logging.getLogger(__name__)

TOOLS = [
    {"type": "web_search_20260209", "name": "web_search"},
    {"type": "web_fetch_20260209", "name": "web_fetch"},
]

_PAUSE_TURN_MAX_ITERATIONS = 10
_EIGHTEEN_MONTHS = timedelta(days=548)
_CONFIDENCE_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


# ---------------------------------------------------------------------------
# Deterministic scoring helpers (items 1 & 2)
# ---------------------------------------------------------------------------


def compute_weighted_total(scores: ScoreBreakdown, weights: dict[str, float]) -> float:
    """Compute weighted total deterministically from pillar scores."""
    total = 0.0
    for pillar_key, weight in weights.items():
        pillar: PillarScore = getattr(scores, pillar_key)
        total += (pillar.score / 5) * weight * 100
    return round(total, 2)


def compute_verdict(
    weighted_total: float,
    pillar_1_score: int,
    thresholds: VerdictThresholds,
) -> Literal["Recommended", "Conditional", "Not Recommended"]:
    """Compute verdict deterministically; Pillar 1 = 1 gates to Not Recommended."""
    if pillar_1_score == 1:
        return "Not Recommended"
    if weighted_total >= thresholds.recommended:
        return "Recommended"
    if weighted_total >= thresholds.conditional:
        return "Conditional"
    return "Not Recommended"


# ---------------------------------------------------------------------------
# Source enrichment (item 6)
# ---------------------------------------------------------------------------


def _parse_publish_date(date_str: str) -> date | None:
    if not date_str:
        return None
    s = date_str.strip()
    if m := re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s):
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    if m := re.fullmatch(r"(\d{4})-(\d{2})", s):
        try:
            return date(int(m.group(1)), int(m.group(2)), 1)
        except ValueError:
            pass
    if m := re.fullmatch(r"(\d{4})", s):
        return date(int(m.group(1)), 7, 1)  # mid-year approximation
    return None


def _enrich_source(entry: SourceEntry, config: Config) -> SourceEntry:
    parsed = _parse_publish_date(entry.publish_date)
    within = parsed is not None and (date.today() - parsed) <= _EIGHTEEN_MONTHS
    on_list = is_on_allowlist(entry.url, entry.publisher, config.trusted_source_allowlist)
    return entry.model_copy(update={"on_allowlist": on_list, "within_18_months": within})


# ---------------------------------------------------------------------------
# Confidence ceiling computation (item 6)
# ---------------------------------------------------------------------------


def _source_confidence_ceiling(
    sources: list[SourceEntry],
) -> Literal["low", "medium", "high"]:
    if not sources:
        return "low"
    recent = sum(1 for s in sources if s.within_18_months)
    trusted = sum(1 for s in sources if s.on_allowlist)
    if recent == 0 or trusted == 0:
        return "low"
    if recent >= 3 and trusted >= 2:
        return "high"
    return "medium"


def _cap(
    value: Literal["low", "medium", "high"],
    ceiling: Literal["low", "medium", "high"],
) -> Literal["low", "medium", "high"]:
    return value if _CONFIDENCE_ORDER[value] <= _CONFIDENCE_ORDER[ceiling] else ceiling


def _apply_confidence_ceiling(
    scores: ScoreBreakdown,
    ceiling: Literal["low", "medium", "high"],
) -> ScoreBreakdown:
    def _capped(p: PillarScore) -> PillarScore:
        new_conf = _cap(p.confidence, ceiling)
        return p if new_conf == p.confidence else p.model_copy(update={"confidence": new_conf})

    return ScoreBreakdown(
        technical_feasibility_reproducibility=_capped(
            scores.technical_feasibility_reproducibility
        ),
        target_profile_relevance=_capped(scores.target_profile_relevance),
        defensive_priority_alignment=_capped(scores.defensive_priority_alignment),
        platform_tooling_compatibility=_capped(scores.platform_tooling_compatibility),
        supply_chain_vector=_capped(scores.supply_chain_vector),
    )


def _rolled_up_confidence(scores: ScoreBreakdown) -> Literal["low", "medium", "high"]:
    return min(  # type: ignore[return-value]
        (
            scores.technical_feasibility_reproducibility.confidence,
            scores.target_profile_relevance.confidence,
            scores.defensive_priority_alignment.confidence,
            scores.platform_tooling_compatibility.confidence,
            scores.supply_chain_vector.confidence,
        ),
        key=lambda c: _CONFIDENCE_ORDER[c],
    )


# ---------------------------------------------------------------------------
# Post-response enrichment (applies items 1, 2, 6 together)
# ---------------------------------------------------------------------------


def _enrich_result(result: EvaluationResult, config: Config) -> EvaluationResult:
    notes = result.notes

    # 1. Deterministic weighted_total
    computed_total = compute_weighted_total(result.scores, config.pillar_weights)
    if abs(result.weighted_total - computed_total) > 1.0:
        notes = (
            f"[Auto: model weighted_total={result.weighted_total:.1f}, "
            f"code-computed={computed_total:.1f}] {notes}"
        ).strip()

    # 2. Deterministic verdict
    p1_score = result.scores.technical_feasibility_reproducibility.score
    computed_verdict = compute_verdict(computed_total, p1_score, config.verdict_thresholds)
    if result.verdict != computed_verdict:
        notes = (
            f"[Auto: model verdict='{result.verdict}', "
            f"overridden to '{computed_verdict}'] {notes}"
        ).strip()

    # 6a. Enrich sources with on_allowlist / within_18_months
    enriched_sources = [_enrich_source(s, config) for s in result.sources]

    # 6b. Confidence ceiling
    ceiling = _source_confidence_ceiling(enriched_sources)
    enriched_scores = _apply_confidence_ceiling(result.scores, ceiling)
    confidence = _rolled_up_confidence(enriched_scores)

    # 6c. Config snapshot
    snapshot = ConfigSnapshot(
        model=config.model,
        target_sector=config.target_sector,
        lab_supported_platforms=config.lab_supported_platforms,
        lab_internet_access=config.lab_internet_access,
        pillar_weights=config.pillar_weights,
        attack_stix_enabled=config.attack_stix_enabled,
    )

    return result.model_copy(
        update={
            "weighted_total": computed_total,
            "verdict": computed_verdict,
            "sources": enriched_sources,
            "scores": enriched_scores,
            "confidence": confidence,
            "notes": notes,
            "config_snapshot": snapshot,
        }
    )


# ---------------------------------------------------------------------------
# Source file helpers
# ---------------------------------------------------------------------------


def _is_url(source: str) -> bool:
    return source.startswith("http://") or source.startswith("https://")


def _describe_source(index: int, source: str) -> str:
    if _is_url(source):
        return f"Source {index}: URL {source} — fetch it with web_fetch."
    path = Path(source)
    if path.suffix.lower() == ".pdf":
        return f"Source {index}: attached PDF '{path.name}'."
    return f"Source {index} ({path.name}):\n{path.read_text()}"


def _build_user_content(
    mode: str,
    actor: str,
    sources: list[str] | None,
    defensive_priority_context: str | None = None,
    attack_stix_context: str | None = None,
) -> list[dict]:
    import base64

    if mode == "discovery":
        content = [{"type": "text", "text": build_user_message(mode, actor)}]
    else:
        assert sources
        content = []
        descriptions: list[str] = []

        for i, source in enumerate(sources, start=1):
            if not _is_url(source):
                path = Path(source)
                if not path.exists():
                    raise FileNotFoundError(f"Source file not found: {path}")
                if path.suffix.lower() == ".pdf":
                    data = base64.standard_b64encode(path.read_bytes()).decode("utf-8")
                    content.append(
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": data,
                            },
                            "title": path.name,
                        }
                    )
            descriptions.append(_describe_source(i, source))

        summary = "\n\n".join(descriptions)
        content.append(
            {"type": "text", "text": build_user_message(mode, actor, source_text=summary)}
        )

    if defensive_priority_context:
        content.append(
            {
                "type": "text",
                "text": (
                    "--- DEFENSIVE PRIORITY ALIGNMENT INPUT (Pillar 3) ---\n"
                    f"{defensive_priority_context}\n"
                    "--- END DEFENSIVE PRIORITY ALIGNMENT INPUT ---"
                ),
            }
        )

    if attack_stix_context:
        content.append(
            {
                "type": "text",
                "text": (
                    "--- MITRE ATT&CK STRUCTURED PROFILE (Pillar 1 & 4 grounding) ---\n"
                    f"{attack_stix_context}\n"
                    "--- END MITRE ATT&CK STRUCTURED PROFILE ---"
                ),
            }
        )

    return content


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------


def evaluate_actor(
    actor: str,
    config: Config,
    source: str | Path | Sequence[str | Path] | None = None,
    defensive_priority_context: str | None = None,
    client: anthropic.Anthropic | None = None,
) -> EvaluationResult:
    """Score a single threat actor.

    `source` may be a single path/URL, a list of them (Mode 1), or omitted
    (Mode 2 — discovery from the actor name alone).
    """
    if source is None:
        sources: list[str] = []
    elif isinstance(source, (str, Path)):
        sources = [str(source)]
    else:
        sources = [str(s) for s in source]

    mode = "source-driven" if sources else "discovery"
    local_paths = [Path(s) for s in sources if not _is_url(s)]
    check_local_sources(local_paths)

    client = client or anthropic.Anthropic()

    attack_stix_context = None
    stix_match_note = ""
    if config.attack_stix_enabled:
        profile = lookup_group(actor)
        if profile is not None:
            attack_stix_context = format_group_context(profile)
            if profile.matched_alias and profile.name != actor:
                stix_match_note = (
                    f"[ATT&CK match: query '{actor}' matched group "
                    f"'{profile.name}' via alias '{profile.matched_alias}'] "
                )

    system_prompt = build_system_prompt(config)
    user_content = _build_user_content(
        mode, actor, sources or None, defensive_priority_context, attack_stix_context
    )
    messages = [{"role": "user", "content": user_content}]

    request_kwargs = dict(
        model=config.model,
        max_tokens=config.max_tokens,
        system=system_prompt,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": output_json_schema()},
        },
        tools=TOOLS,
    )

    response = client.messages.create(messages=messages, **request_kwargs)

    # pause_turn means the server-side tool loop hit its iteration cap; resend
    # to let it resume. Cap iterations to avoid unbounded spin.
    iterations = 0
    while response.stop_reason == "pause_turn":
        iterations += 1
        if iterations >= _PAUSE_TURN_MAX_ITERATIONS:
            raise RuntimeError(
                f"Evaluation of '{actor}' hit the pause_turn iteration cap "
                f"({_PAUSE_TURN_MAX_ITERATIONS}). The model may be in an "
                "unresolvable tool loop."
            )
        messages = [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": response.content},
        ]
        response = client.messages.create(messages=messages, **request_kwargs)

    if response.stop_reason == "refusal":
        raise RuntimeError(
            f"Model declined to evaluate '{actor}': {response.stop_details}"
        )

    if response.stop_reason == "max_tokens":
        raise RuntimeError(
            f"Model hit the token limit ({config.max_tokens}) while evaluating "
            f"'{actor}'. Consider raising max_tokens in config or using fewer sources."
        )

    text_block = next(
        (block for block in response.content if block.type == "text"), None
    )
    if text_block is None:
        raise RuntimeError(
            f"No text block in model response for '{actor}' "
            f"(stop_reason={response.stop_reason!r}). The model may have "
            "stopped mid-generation."
        )

    # Parse and validate, with one retry on failure.
    result = _parse_and_validate(text_block.text, actor, config, client, request_kwargs, messages)

    result = result.model_copy(update={"mode": mode})
    result = _enrich_result(result, config)

    # Prepend STIX alias-match note if present.
    if stix_match_note and not result.notes.startswith(stix_match_note):
        result = result.model_copy(update={"notes": (stix_match_note + result.notes).strip()})

    return result


def _parse_and_validate(
    text: str,
    actor: str,
    config: Config,
    client: anthropic.Anthropic,
    request_kwargs: dict,
    messages: list[dict],
) -> EvaluationResult:
    """Parse JSON and validate; retry once on failure."""
    try:
        return EvaluationResult.model_validate(json.loads(text))
    except Exception as first_exc:
        logger.warning(
            "Failed to parse model response for '%s' (%s); retrying once.",
            actor,
            first_exc,
        )

    # Retry: send an explicit "please output valid JSON" continuation.
    retry_messages = messages + [
        {"role": "assistant", "content": [{"type": "text", "text": text}]},
        {
            "role": "user",
            "content": (
                "Your previous response was not valid JSON matching the required schema. "
                "Please output only the JSON object, with no additional text."
            ),
        },
    ]
    retry_response = client.messages.create(messages=retry_messages, **request_kwargs)
    retry_block = next(
        (b for b in retry_response.content if b.type == "text"), None
    )
    if retry_block is None:
        raise RuntimeError(
            f"No text block in retry response for '{actor}' "
            f"(stop_reason={retry_response.stop_reason!r})."
        )
    try:
        return EvaluationResult.model_validate(json.loads(retry_block.text))
    except Exception as retry_exc:
        raise RuntimeError(
            f"Could not parse model response for '{actor}' after retry: {retry_exc}"
        ) from retry_exc
