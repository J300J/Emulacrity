from __future__ import annotations

import json as json_module
from pathlib import Path
from typing import List, Optional

import anthropic
import typer
import yaml
from rich.console import Console
from rich.table import Table

from emulacrity.allowlist import EXCLUDED_SOURCES
from emulacrity.config import Config, load_config, parse_weight_overrides
from emulacrity.defensive import gather_defensive_priority_context
from emulacrity.preflight import PreflightError
from emulacrity.report import write_pdf
from emulacrity.scoring import evaluate_actor

app = typer.Typer(
    help="Emulacrity — CTI-driven purple team emulation candidate scoring.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Inspect and initialize Emulacrity configuration.")
app.add_typer(config_app, name="config")

console = Console()


@app.command()
def evaluate(
    actor: str = typer.Argument(..., help="Threat actor name, e.g. 'APT34'."),
    source: List[str] = typer.Option(
        [],
        "--source",
        "-s",
        help="Path to a PDF/text report, or a URL. Repeatable — pass it multiple "
        "times to use several PDFs/reports as the Mode 1 (source-driven) material. "
        "Omit entirely for Mode 2 (discovery).",
    ),
    config_path: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to a config file (YAML or JSON)."
    ),
    sector: Optional[str] = typer.Option(None, "--sector", help="Override target_sector."),
    internet_access: Optional[str] = typer.Option(
        None,
        "--internet-access",
        help="Override lab_internet_access: 'connected' or 'air_gapped'.",
    ),
    platforms: List[str] = typer.Option(
        [],
        "--platforms",
        "-p",
        help="Override lab_supported_platforms. Repeatable. Valid: windows_server, "
        "windows_endpoint, macos, linux, cloud.",
    ),
    weight: List[str] = typer.Option(
        [],
        "--weight",
        "-w",
        help="Override one pillar weight as KEY=VALUE, e.g. --weight technical=0.4. "
        "Repeatable — only the given pillars change, the rest keep their configured "
        "value. Short keys: technical, sector, defensive, platform, supply_chain "
        "(or the full pillar_weights key). All five must still sum to 1.0.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write the JSON result to this file."
    ),
    pdf: Optional[Path] = typer.Option(
        None, "--pdf", help="Also write a PDF transcription of the result to this file."
    ),
    table: bool = typer.Option(
        False, "--table", help="Also print a human-readable summary table."
    ),
    defensive_context: Optional[str] = typer.Option(
        None,
        "--defensive-context",
        help="Pillar 3 input: freeform pasted context (ticketing export, Slack "
        "thread, SOC notes). Mutually exclusive with --defensive-context-file.",
    ),
    defensive_context_file: Optional[Path] = typer.Option(
        None,
        "--defensive-context-file",
        help="Pillar 3 input: path to a file with freeform context, instead of "
        "pasting it inline.",
    ),
    defensive_adapter: Optional[Path] = typer.Option(
        None,
        "--defensive-adapter",
        help="Pillar 3 input: path to a JSON file conforming to the "
        "defensive_priority_source adapter schema (see Emulacrity.md).",
    ),
    no_interactive: bool = typer.Option(
        False,
        "--no-interactive",
        help="Skip interactive guided-prompt questions (Pillar 3 defaults to neutral).",
    ),
) -> None:
    """Score a single threat actor against the Emulacrity rubric."""
    overrides = {
        "target_sector": sector,
        "lab_internet_access": internet_access,
        "lab_supported_platforms": platforms or None,
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
    except anthropic.RateLimitError as exc:
        retry_after = exc.response.headers.get("retry-after")
        suffix = f" Retry after {retry_after}s." if retry_after else ""
        console.print(f"[red]Rate limited by the Anthropic API.{suffix}[/red]")
        raise typer.Exit(code=1) from exc
    except anthropic.APIStatusError as exc:
        error_type = getattr(exc, "type", None) or "api_error"
        detail = exc.message
        if isinstance(exc.body, dict):
            detail = exc.body.get("error", {}).get("message", detail)
        console.print(f"[red]Anthropic API error ({exc.status_code} {error_type}): {detail}[/red]")
        raise typer.Exit(code=1) from exc
    except anthropic.APIConnectionError as exc:
        console.print(f"[red]Could not reach the Anthropic API: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    payload = result.model_dump()
    if output:
        output.write_text(json_module.dumps(payload, indent=2))
        console.print(f"[green]Wrote result to {output}[/green]")
    else:
        console.print_json(data=payload)

    if pdf:
        write_pdf(result, pdf)
        console.print(f"[green]Wrote PDF report to {pdf}[/green]")

    if table:
        _print_summary_table(result)


def _print_summary_table(result) -> None:
    verdict_style = {
        "Recommended": "green",
        "Conditional": "yellow",
        "Not Recommended": "red",
    }.get(result.verdict, "white")

    t = Table(title=f"{result.actor} — [{verdict_style}]{result.verdict}[/{verdict_style}]")
    t.add_column("Pillar")
    t.add_column("Score", justify="right")
    for name, pillar in result.scores.__dict__.items():
        t.add_row(name.replace("_", " ").title(), f"{pillar.score}/5")
    t.add_row("Weighted Total", f"{result.weighted_total:.1f}/100", style="bold")
    console.print(t)


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
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Print the resolved configuration (built-in defaults + file overrides)."""
    cfg = load_config(config_path=config_path)
    console.print_json(data=cfg.model_dump())


@app.command()
def sources(
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """List the trusted source allowlist, and sources excluded by default."""
    cfg = load_config(config_path=config_path)
    console.print("[bold]Trusted source allowlist:[/bold]")
    for source_name in cfg.trusted_source_allowlist:
        console.print(f"  - {source_name}")
    console.print("\n[bold]Excluded by default:[/bold]")
    for source_name, reason in EXCLUDED_SOURCES.items():
        console.print(f"  - {source_name} ({reason})")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
