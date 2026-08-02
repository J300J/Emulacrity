from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional, Sequence, Union

import anthropic

from emulacrity.attack_stix import format_group_context, lookup_group
from emulacrity.config import Config
from emulacrity.preflight import check_local_sources
from emulacrity.prompts import build_system_prompt, build_user_message
from emulacrity.schema import EvaluationResult, output_json_schema

MODEL = "claude-sonnet-5"
MAX_TOKENS = 8000

TOOLS = [
    {"type": "web_search_20260209", "name": "web_search"},
    {"type": "web_fetch_20260209", "name": "web_fetch"},
]


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
    sources: Optional[list[str]],
    defensive_priority_context: Optional[str] = None,
    attack_stix_context: Optional[str] = None,
) -> list[dict]:
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


def evaluate_actor(
    actor: str,
    config: Config,
    source: Optional[Union[str, Path, Sequence[Union[str, Path]]]] = None,
    defensive_priority_context: Optional[str] = None,
    client: Optional[anthropic.Anthropic] = None,
) -> EvaluationResult:
    """Score a single threat actor.

    `source` may be a single path/URL, a list of them (Mode 1 — one or more
    PDFs/text files/links used as the primary source material), or omitted
    entirely (Mode 2 — discovery from the actor name alone).

    `defensive_priority_context` is whatever Pillar 3 input was gathered via
    guided prompts, freeform paste, or the adapter schema (see defensive.py).
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
    if config.attack_stix_enabled:
        profile = lookup_group(actor)
        if profile is not None:
            attack_stix_context = format_group_context(profile)

    system_prompt = build_system_prompt(config)
    user_content = _build_user_content(
        mode, actor, sources or None, defensive_priority_context, attack_stix_context
    )
    messages = [{"role": "user", "content": user_content}]

    request_kwargs = dict(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system_prompt,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": output_json_schema()},
        },
        tools=TOOLS,
    )

    response = client.messages.create(messages=messages, **request_kwargs)

    # web_search/web_fetch run their own internal iteration loop; if it hits
    # the server-side cap the turn pauses rather than finishing. Resend the
    # conversation as-is (no extra "continue" message) to let it resume.
    while response.stop_reason == "pause_turn":
        messages = [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": response.content},
        ]
        response = client.messages.create(messages=messages, **request_kwargs)

    if response.stop_reason == "refusal":
        raise RuntimeError(f"Model declined to evaluate '{actor}': {response.stop_details}")

    text = next(block.text for block in response.content if block.type == "text")
    result = EvaluationResult.model_validate(json.loads(text))
    return result.model_copy(update={"mode": mode})
