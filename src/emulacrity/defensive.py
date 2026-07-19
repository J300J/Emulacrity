"""Defensive Priority Alignment (Pillar 3) input gathering.

Emulacrity has no live backend of its own, so this pillar is scored from
whatever context the user supplies at evaluation time — see Emulacrity.md >
Pillar 3 > "How the user provides this input" and > Configurable Parameters >
`defensive_priority_source`. Three mechanisms:

- guided_prompts (default): interactively ask a short set of targeted
  questions per actor.
- freeform: the user pastes/imports unstructured context (ticketing export,
  Slack thread, SOC notes).
- adapter: the user supplies a JSON array conforming to the documented
  schema, produced by their own internal CTI/ticketing system.

If nothing is supplied, Pillar 3 defaults to a neutral score (3 — Routine
Awareness) rather than guessing or penalizing — enforced in the system
prompt (prompts.py), not here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

GUIDED_QUESTIONS: list[str] = [
    "Is this actor being actively hunted?",
    "Any internal alerts on this actor in the last 90 days?",
    "Does this overlap with a recent assessment/red-team finding?",
]


def prompt_guided_questions(actor: str) -> Optional[str]:
    """Interactively ask the guided-prompt questions for one actor.

    Returns None (→ Pillar 3 defaults to neutral) if the user skips every
    question, or if stdin isn't an interactive terminal.
    """
    if not console.is_terminal:
        return None

    console.print(f"\n[bold]Defensive Priority Alignment — {actor}[/bold]")
    console.print("Press Enter to skip a question (defaults Pillar 3 to neutral).\n")

    answers: list[str] = []
    for question in GUIDED_QUESTIONS:
        response = console.input(f"  {question} ").strip()
        if response:
            answers.append(f"Q: {question}\nA: {response}")

    return "\n\n".join(answers) if answers else None


def load_freeform_context(text: Optional[str], file: Optional[Path]) -> Optional[str]:
    """Load freeform pasted/imported context from an inline string or a file."""
    if text and file:
        raise ValueError(
            "Provide either --defensive-context or --defensive-context-file, not both."
        )
    if file:
        if not file.exists():
            raise FileNotFoundError(f"Defensive context file not found: {file}")
        return file.read_text()
    return text


def load_adapter_context(path: Path, actor: str) -> Optional[str]:
    """Load and match one entry from a defensive_priority_source adapter file.

    Expects a JSON array conforming to the documented schema:
    [{"actor": "...", "alert_count_90d": 0, "last_seen": "YYYY-MM-DD",
      "active_hunt": true, "notes": "..."}]
    """
    if not path.exists():
        raise FileNotFoundError(f"Defensive priority adapter file not found: {path}")

    try:
        entries = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"'{path}' is not valid JSON: {exc}") from exc

    if not isinstance(entries, list):
        raise ValueError(
            f"'{path}' must be a JSON array conforming to the documented "
            "defensive_priority_source adapter schema (see Emulacrity.md > "
            "Configurable Parameters)."
        )

    match = next(
        (
            entry
            for entry in entries
            if isinstance(entry, dict)
            and str(entry.get("actor", "")).strip().lower() == actor.strip().lower()
        ),
        None,
    )

    if match is None:
        console.print(
            f"[yellow]No adapter entry found for '{actor}' in {path} — "
            "Pillar 3 will default to neutral.[/yellow]"
        )
        return None

    lines = [f"{key}: {value}" for key, value in match.items() if key != "actor"]
    return "\n".join(lines)


def gather_defensive_priority_context(
    *,
    actor: str,
    source_mode: str,
    interactive: bool,
    context_text: Optional[str],
    context_file: Optional[Path],
    adapter_path: Optional[Path],
) -> Optional[str]:
    """Resolve Pillar 3 input for one actor.

    Whichever concrete input is actually supplied wins, regardless of
    `source_mode` (adapter > freeform > guided prompts). If nothing is
    supplied, falls back to the deployment's configured `source_mode`.
    """
    if adapter_path is not None:
        return load_adapter_context(adapter_path, actor)

    if context_text is not None or context_file is not None:
        return load_freeform_context(context_text, context_file)

    if source_mode == "guided_prompts":
        return prompt_guided_questions(actor) if interactive else None

    console.print(
        f"[yellow]defensive_priority_source is '{source_mode}' but no matching "
        "input was provided (--defensive-context/--defensive-context-file or "
        "--defensive-adapter) — Pillar 3 will default to neutral.[/yellow]"
    )
    return None
