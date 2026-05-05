"""CLI interface for safe-browser."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from . import __version__
from .adapters import AdapterError, get_input
from .config import Config

app = typer.Typer(
    name="safe-browser",
    help="Screen browser content for prompt injection attacks.",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool):
    if value:
        print(f"safe-browser {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-V", callback=version_callback, is_eager=True, help="Show version"),
    ] = None,
):
    pass


def _run_scan(
    content: str | None,
    file: Path | None,
    output_json: bool,
    quiet: bool,
    config_path: Path | None,
    threshold: float | None,
    no_ml: bool,
):
    """Shared logic for check/scan commands."""
    from .scanner import scan as run_scan

    # Load config
    config = Config.from_file(config_path)
    if threshold is not None:
        config.block_threshold = threshold
    if no_ml:
        config.use_ml = False

    logging.basicConfig(level=getattr(logging, config.log_level, logging.WARNING))

    # Read input
    try:
        file_str = str(file) if file is not None else None
        text = get_input(content=content, file=file_str)
    except AdapterError as e:
        if not quiet:
            typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=2)

    # Scan
    result = run_scan(text, config)

    # Output
    if not quiet:
        if output_json:
            typer.echo(json.dumps(result.to_dict(), indent=2))
        else:
            _print_human(result, len(text))

    raise typer.Exit(code=result.exit_code)


@app.command()
def check(
    content: Annotated[Optional[str], typer.Option("--content", "-c", help="Scan a string directly")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Scan file contents")] = None,
    output_json: Annotated[bool, typer.Option("--json", help="Output JSON")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only exit code, no output")] = False,
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", help="Config file path"),
    ] = None,
    threshold: Annotated[Optional[float], typer.Option("--threshold", help="Override block threshold")] = None,
    no_ml: Annotated[bool, typer.Option("--no-ml", help="Skip ML model, rules only")] = False,
):
    """Check content for prompt injection attacks (primary command)."""
    _run_scan(content, file, output_json, quiet, config_path, threshold, no_ml)


@app.command()
def scan(
    content: Annotated[Optional[str], typer.Option("--content", "-c", help="Scan a string directly")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Scan file contents")] = None,
    output_json: Annotated[bool, typer.Option("--json", help="Output JSON")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only exit code, no output")] = False,
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", help="Config file path"),
    ] = None,
    threshold: Annotated[Optional[float], typer.Option("--threshold", help="Override block threshold")] = None,
    no_ml: Annotated[bool, typer.Option("--no-ml", help="Skip ML model, rules only")] = False,
):
    """Alias for check — scan content for prompt injection attacks."""
    _run_scan(content, file, output_json, quiet, config_path, threshold, no_ml)


@app.command()
def doctor():
    """Pre-flight check: verify models are downloadable and config is valid."""
    typer.echo("Checking configuration...")

    config = Config.from_file()
    typer.echo(f"  Config:    OK (model: {config.model_name})")
    typer.echo(f"  Device:    {config.device}")
    typer.echo(f"  Rules:     {'enabled' if config.rules_enabled else 'disabled'}")
    typer.echo(f"  ML model:  {'enabled' if config.use_ml else 'disabled'}")

    if config.use_ml:
        typer.echo(f"\nLoading model {config.model_name}...")
        try:
            from .models import get_model

            model = get_model(config.model_name, config.device)
            typer.secho(f"  Model loaded: {model.model_name} ({model.num_labels} labels)", fg=typer.colors.GREEN)

            # Quick self-test
            score, label = model.predict("Hello, how are you?")
            typer.echo(f"  Self-test: score={score:.4f} label={label}")
            typer.secho("\nAll checks passed.", fg=typer.colors.GREEN, bold=True)
        except Exception as e:
            typer.secho(f"  Model load failed: {e}", fg=typer.colors.RED)
            if config.fallback_to_rules:
                typer.echo("  Fallback to rules-only mode is enabled.")
            raise typer.Exit(code=1)
    else:
        typer.secho("\nConfig check passed (ML disabled).", fg=typer.colors.GREEN, bold=True)


@app.command()
def models():
    """List available detection models."""
    typer.echo("Available detection models:\n")
    typer.echo("  meta-llama/Llama-Prompt-Guard-2-86M")
    typer.echo("    Fast, lightweight (86M params). Good for real-time screening.\n")
    typer.echo("  protectai/deberta-v3-base-prompt-injection-v2")
    typer.echo("    DeBERTa-based, balanced accuracy/speed. Default.\n")
    typer.echo("  perplexity-ai/browsesafe  (Phase 2)")
    typer.echo("    Fine-tuned for browser-specific injection patterns.\n")
    typer.echo("  openai/gpt-oss-safeguard-20b  (Phase 2)")
    typer.echo("    Large model, highest accuracy, slower inference.\n")
    typer.echo("  rule-based  (always available)")
    typer.echo("    Regex pattern matching. No model download needed.")


def _print_human(result, text_length: int) -> None:
    """Print human-readable scan results."""
    colors = {"safe": typer.colors.GREEN, "suspicious": typer.colors.YELLOW, "malicious": typer.colors.RED}
    color = colors.get(result.decision, typer.colors.WHITE)

    typer.echo()
    typer.secho(f"  Decision: {result.decision.upper()}", fg=color, bold=True)
    typer.echo(f"  Score:    {result.score:.4f}")
    typer.echo(f"  Input:    {text_length} chars")

    if result.model_score is not None:
        typer.echo(f"  Model:    {result.model_label} ({result.model_score:.4f})")
    else:
        typer.echo("  Model:    not used")

    if result.rule_matches:
        typer.echo(f"  Rules:    {', '.join(result.rule_matches)}")
    else:
        typer.echo("  Rules:    no matches")

    typer.echo()
