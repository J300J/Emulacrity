from __future__ import annotations

import json as json_module
from pathlib import Path

import anthropic
import typer
import yaml
from rich.console import Console
from rich.table import Table

from emulacrity.allowlist import EXCLUDED_SOURCES
from emulacrity.attack_stix import DEFAULT_CACHE_PATH, refresh_bundle
from emulacrity.config import Config, load_config, parse_weight_overrides
from emulacrity.defensive import gather_defensive_priority_context
from emulacrity.preflight import PreflightError
from emulacrity.ranking import NEAR_TIE_THRESHOLD, build_rank_output, rank_actors, sort_results
from emulacrity.report import write_pdf
from emulacrity.schema import EvaluationResult
from emulacrity.scoring import evaluate_actor

app = typer.Typer(
    help="Emulacrity — CTI-driven purple team emulation candidate scoring.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Inspect and initialize Emulacrity configuration.")
stix_app = typer.Typer(help="Manage the local ATT&CK STIX bundle.")
app.add_typer(config_app, name="config")
app.add_typer(stix_app, name="stix")

console = Console()

_API_ERRORS = (
    anthropic.RateLimitError,
    anthropic.APIStatusError,
    anthropic.APIConnectionError,
)


def _handle_api_error(exc: Exception) -> None:
    if isinstance(exc, anthropic.RateLimitError):
        retry_after = exc.response.headers.get("retry-after")
        suffix = f" Retry after {retry_after}s." if retry_after else ""
        console.print(f"[red]Rate limited by the Anthropic API.{suffix}[/red]")
    elif isinstance(exc, anthropic.APIStatusError):
        error_type = getattr(exc, "type", None) or "api_error"
        detail = exc.message
        if isinstance(exc.body, dict):
            detail = exc.body.get("error", {}).get("message", detail)
        console.print(
            f"[red]Anthropic API error ({exc.status_code} {error_type}): {detail}[/red]"
        )
    elif isinstance(exc, anthropic.APIConnectionError):
        console.print(f"[red]Could not reach the Anthropic API: {exc}[/red]")


@app.command()
def evaluate(
    actor: str = typer.Argument(..., help="Threat actor name, e.g. 'APT34'."),
    source: list[str] = typer.Option(
        [],
        "--source",
        "-s",
        help="Path to a PDF/text report, or a URL. Repeatable.",
    ),
    config_path: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a config file (YAML or JSON)."
    ),
    sector: str | None = typer.Option(None, "--sector", help="Override target_sector."),
    internet_access: str | None = typer.Option(
        None,
        "--internet-access",
        help="Override lab_internet_access: 'connected' or 'air_gapped'.",
    ),
    platforms: list[str] = typer.Option(
        [],
        "--platforms",
        "-p",
        help="Override lab_supported_platforms. Repeatable.",
    ),
    weight: list[str] = typer.Option(
        [],
        "--weight",
        "-w",
        help="Override one pillar weight as KEY=VALUE, e.g. --weight technical=0.4.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the JSON result to this file."
    ),
    pdf: Path | None = typer.Option(
        None, "--pdf", help="Also write a PDF transcription of the result to this file."
    ),
    format: str | None = typer.Option(
        None,
        "--format",
        help="Stdout output format: json (default), table, md.",
    ),
    table: bool = typer.Option(
        False,
        "--table",
        hidden=True,
        help="Deprecated; use --format table.",
    ),
    defensive_context: str | None = typer.Option(
        None,
        "--defensive-context",
        help="Pillar 3 input: freeform pasted context.",
    ),
    defensive_context_file: Path | None = typer.Option(
        None,
        "--defensive-context-file",
        help="Pillar 3 input: path to a file with freeform context.",
    ),
    defensive_adapter: Path | None = typer.Option(
        None,
        "--defensive-adapter",
        help="Pillar 3 input: path to a JSON adapter file.",
    ),
    no_interactive: bool = typer.Option(
        False,
        "--no-interactive",
        help="Skip interactive guided-prompt questions.",
    ),
    no_attack_stix: bool = typer.Option(
        False,
        "--no-attack-stix",
        help="Skip the MITRE ATT&CK structured lookup for this run.",
    ),
) -> None:
    """Score a single threat actor against the Emulacrity rubric."""
    effective_format = format or ("table" if table else "json")

    overrides = {
        "target_sector": sector,
        "lab_internet_access": internet_access,
        "lab_supported_platforms": platforms or None,
        "attack_stix_enabled": False if no_attack_stix else None,
    }

    try:
        if weight:
            overrides["pillar_weight_overrides"] = parse_weight_overrides(weight)
        cfg = load_config(config_path=config_path, overrides=overrides)
        defensive_priority_context = gather_defensive_priority_context(
            actor=actor,
            source_mode=cfg.defensive_priority_source,
            interactive=not no_interactive,
            context_text=defensive_context,
            context_file=defensive_context_file,
            adapter_path=defensive_adapter,
        )
        result = evaluate_actor(
            actor=actor,
            config=cfg,
            source=source,
            defensive_priority_context=defensive_priority_context,
        )
    except (PreflightError, ValueError, FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except _API_ERRORS as exc:  # type: ignore[misc]
        _handle_api_error(exc)
        raise typer.Exit(code=1) from exc

    payload = result.model_dump()
    if output:
        output.write_text(json_module.dumps(payload, indent=2))
        console.print(f"[green]Wrote result to {output}[/green]")

    if effective_format == "table":
        _print_summary_table(result)
    elif effective_format == "md":
        console.print(_format_markdown(result))
    else:
        if not output:
            console.print_json(data=payload)

    if pdf:
        write_pdf(result, pdf)
        console.print(f"[green]Wrote PDF report to {pdf}[/green]")


@app.command()
def rank(
    actors: list[str] = typer.Argument(
        ...,
        help="Threat actor names to rank, e.g. APT34 FIN7 'Scattered Spider'.",
    ),
    actors_file: Path | None = typer.Option(
        None,
        "--actors-file",
        help="File with one actor name per line (merged with positional args).",
    ),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
    sector: str | None = typer.Option(None, "--sector"),
    internet_access: str | None = typer.Option(None, "--internet-access"),
    platforms: list[str] = typer.Option([], "--platforms", "-p"),
    weight: list[str] = typer.Option([], "--weight", "-w"),
    defensive_adapter: Path | None = typer.Option(
        None,
        "--defensive-adapter",
        help="JSON adapter file covering all actors for Pillar 3.",
    ),
    concurrency: int = typer.Option(3, "--concurrency", help="Max parallel evaluations."),
    max_actors: int = typer.Option(
        10, "--max-actors", help="Hard cap on actor count (cost guard)."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write combined JSON."),
    no_attack_stix: bool = typer.Option(False, "--no-attack-stix"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero if any actor fails (default: continue)."
    ),
) -> None:
    """Score multiple actors and rank them by weighted total."""
    all_actors = list(actors)
    if actors_file:
        if not actors_file.exists():
            console.print(f"[red]Actors file not found: {actors_file}[/red]")
            raise typer.Exit(code=1)
        lines = [ln.strip() for ln in actors_file.read_text().splitlines() if ln.strip()]
        all_actors.extend(lines)

    all_actors = list(dict.fromkeys(all_actors))  # deduplicate, preserve order

    if not all_actors:
        console.print("[red]No actors specified.[/red]")
        raise typer.Exit(code=1)

    if len(all_actors) > max_actors:
        console.print(
            f"[red]{len(all_actors)} actors exceeds --max-actors={max_actors}. "
            "Pass --max-actors N to raise the limit.[/red]"
        )
        raise typer.Exit(code=1)

    overrides = {
        "target_sector": sector,
        "lab_internet_access": internet_access,
        "lab_supported_platforms": platforms or None,
        "attack_stix_enabled": False if no_attack_stix else None,
    }
    try:
        if weight:
            overrides["pillar_weight_overrides"] = parse_weight_overrides(weight)
        cfg = load_config(config_path=config_path, overrides=overrides)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    n = len(all_actors)
    console.print(
        f"Ranking [bold]{n}[/bold] actor(s) — each is a full high-effort run with "
        "web search. Continue? [y/N] ",
        end="",
    )
    answer = console.input("").strip().lower()
    if answer not in {"y", "yes"}:
        console.print("Aborted.")
        raise typer.Exit(code=0)

    console.print(f"Running {n} evaluation(s) with concurrency={concurrency}…")
    try:
        results, errors = rank_actors(
            all_actors,
            cfg,
            defensive_adapter=defensive_adapter,
            concurrency=concurrency,
        )
    except _API_ERRORS as exc:  # type: ignore[misc]
        _handle_api_error(exc)
        raise typer.Exit(code=1) from exc

    for actor_name, err in errors:
        console.print(f"[yellow]Error scoring '{actor_name}': {err}[/yellow]")

    if not results:
        console.print("[red]All evaluations failed.[/red]")
        raise typer.Exit(code=1)

    payload = build_rank_output(results, errors, cfg)
    ranked = sort_results(results)
    _print_rank_table(ranked, cfg)

    if output:
        output.write_text(json_module.dumps(payload, indent=2))
        console.print(f"[green]Wrote ranking to {output}[/green]")
    else:
        console.print_json(data=payload)

    if strict and errors:
        raise typer.Exit(code=1)


def _print_rank_table(results: list[EvaluationResult], config: Config) -> None:
    from emulacrity.ranking import compute_ranking_deltas

    deltas = compute_ranking_deltas(results, config.pillar_weights)
    t = Table(title="Emulacrity Ranking")
    t.add_column("Rank", justify="right")
    t.add_column("Actor")
    t.add_column("P1", justify="right")
    t.add_column("P2", justify="right")
    t.add_column("P3", justify="right")
    t.add_column("P4", justify="right")
    t.add_column("P5", justify="right")
    t.add_column("Total", justify="right")
    t.add_column("Verdict")
    t.add_column("Note")

    for i, result in enumerate(results):
        s = result.scores
        verdict_style = {
            "Recommended": "green",
            "Conditional": "yellow",
            "Not Recommended": "red",
        }.get(result.verdict, "white")

        note = ""
        if result.scores.technical_feasibility_reproducibility.score == 1:
            note = "⛔ gated"
        elif i < len(deltas) and abs(deltas[i]["gap"]) <= NEAR_TIE_THRESHOLD:
            note = "≈ near tie"

        t.add_row(
            str(i + 1),
            result.actor,
            str(s.technical_feasibility_reproducibility.score),
            str(s.target_profile_relevance.score),
            str(s.defensive_priority_alignment.score),
            str(s.platform_tooling_compatibility.score),
            str(s.supply_chain_vector.score),
            f"{result.weighted_total:.1f}",
            f"[{verdict_style}]{result.verdict}[/{verdict_style}]",
            note,
        )
    console.print(t)


def _print_summary_table(result: EvaluationResult) -> None:
    verdict_style = {
        "Recommended": "green",
        "Conditional": "yellow",
        "Not Recommended": "red",
    }.get(result.verdict, "white")

    t = Table(
        title=(
            f"{result.actor} — [{verdict_style}]{result.verdict}[/{verdict_style}]"
            f" (confidence: {result.confidence})"
        )
    )
    t.add_column("Pillar")
    t.add_column("Score", justify="right")
    t.add_column("Confidence")
    for name, pillar in result.scores.__dict__.items():
        t.add_row(
            name.replace("_", " ").title(),
            f"{pillar.score}/5",
            pillar.confidence,
        )
    t.add_row("Weighted Total", f"{result.weighted_total:.1f}/100", "", style="bold")
    console.print(t)


def _format_markdown(result: EvaluationResult) -> str:
    lines = [
        f"# Emulacrity Evaluation: {result.actor}",
        "",
        f"**Verdict:** {result.verdict}  ",
        f"**Weighted Total:** {result.weighted_total:.1f}/100  ",
        f"**Mode:** {result.mode}  ",
        f"**Confidence:** {result.confidence}",
        "",
        "## Pillar Scores",
        "",
        "| Pillar | Score | Confidence | Justification |",
        "|--------|-------|------------|---------------|",
    ]
    pillar_labels = {
        "technical_feasibility_reproducibility": "Technical Feasibility & Reproducibility",
        "target_profile_relevance": "Target Profile Relevance",
        "defensive_priority_alignment": "Defensive Priority Alignment",
        "platform_tooling_compatibility": "Platform & Tooling Compatibility",
        "supply_chain_vector": "Third-Party / Supply Chain Vector",
    }
    for key, label in pillar_labels.items():
        p = getattr(result.scores, key)
        lines.append(f"| {label} | {p.score}/5 | {p.confidence} | {p.justification} |")

    if result.sources:
        lines += ["", "## Sources", ""]
        for s in result.sources:
            title = s.title or s.url or "(untitled)"
            meta = []
            if s.publisher:
                meta.append(s.publisher)
            if s.publish_date:
                meta.append(s.publish_date)
            flags = []
            if s.on_allowlist:
                flags.append("trusted")
            if s.within_18_months:
                flags.append("recent")
            if flags:
                meta.append(f"[{', '.join(flags)}]")
            meta_str = " — ".join(meta)
            lines.append(f"- **{title}**" + (f" — {meta_str}" if meta_str else ""))

    lines += ["", "## Notes", "", result.notes or "—"]
    return "\n".join(lines)


@config_app.command("init")
def config_init(
    path: Path = typer.Option(
        Path("emulacrity.yaml"), "--path", help="Where to write the config file."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a starter emulacrity.yaml with the built-in defaults."""
    if path.exists() and not force:
        console.print(f"[red]{path} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

    default_cfg = Config(
        target_sector="Financial Services",
        lab_supported_platforms=["windows_endpoint", "windows_server"],
    )
    path.write_text(yaml.safe_dump(default_cfg.model_dump(), sort_keys=False))
    console.print(f"[green]Wrote default config to {path}[/green]")


@config_app.command("show")
def config_show(
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Print the resolved configuration (built-in defaults + file overrides)."""
    cfg = load_config(config_path=config_path)
    console.print_json(data=cfg.model_dump())


@app.command()
def sources(
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """List the trusted source allowlist, and sources excluded by default."""
    cfg = load_config(config_path=config_path)
    console.print("[bold]Trusted source allowlist:[/bold]")
    for source_name in cfg.trusted_source_allowlist:
        console.print(f"  - {source_name}")
    console.print("\n[bold]Excluded by default:[/bold]")
    for source_name, reason in EXCLUDED_SOURCES.items():
        console.print(f"  - {source_name} ({reason})")


@stix_app.command("refresh")
def stix_refresh(
    cache_path: Path = typer.Option(
        DEFAULT_CACHE_PATH,
        "--path",
        help="Where to write the refreshed bundle.",
    ),
) -> None:
    """Fetch the latest ATT&CK STIX bundle from MITRE and store it locally."""
    console.print("Fetching ATT&CK STIX bundle from MITRE...")
    try:
        refresh_bundle(cache_path)
    except Exception as exc:
        console.print(f"[red]Failed to refresh ATT&CK STIX data: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]ATT&CK STIX bundle refreshed → {cache_path}[/green]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
