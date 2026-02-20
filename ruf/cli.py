"""Command-line interface for RUF."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .config import Config

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ruf")
def cli() -> None:
    """RUF — Multi-pass AI Security Auditor."""


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--model", "-m", default=None, help="Override AI model name.")
@click.option("--nav-model", default=None, help="Faster model for navigation/tooling only.")
@click.option("--api-key", "-k", default=None, help="OpenAI API key (or set OPENAI_API_KEY).")
@click.option("--base-url", default=None, help="OpenAI-compatible API base URL.")
@click.option("--output", "-o", default="./audit_reports", help="Output directory for reports.")
@click.option("--temperature", "-t", default=0.1, type=float, help="Sampling temperature (0.0–1.0).")
@click.option("--service-tier", default=None, help="Service tier: priority or default.")
@click.option("--reasoning-effort", default=None, help="GPT-5 reasoning_effort: none|low|medium|high|xhigh.")
@click.option("--verbosity", default=None, help="GPT-5 verbosity: low|medium|high.")
@click.option("--nav-reasoning-effort", default=None, help="Navigation reasoning effort: none|low|medium|high|xhigh.")
@click.option("--nav-verbosity", default=None, help="Navigation verbosity: low|medium|high.")
@click.option("--prompt-cache-retention", default=None, help="Prompt cache retention (Responses API): 24h|in-memory.")
@click.option("--max-tool-iterations", default=None, type=int, help="Max tool iterations per pass.")
def audit(
    target: str,
    model: str | None,
    nav_model: str | None,
    api_key: str | None,
    base_url: str | None,
    output: str,
    temperature: float,
    service_tier: str | None,
    reasoning_effort: str | None,
    verbosity: str | None,
    nav_reasoning_effort: str | None,
    nav_verbosity: str | None,
    prompt_cache_retention: str | None,
    max_tool_iterations: int | None,
) -> None:
    """Run a full security audit on TARGET (directory or file)."""
    from .pipeline import AuditPipeline
    from .report import save_report

    config = Config.from_env()
    if model:
        config.model = model
    if nav_model:
        config.navigation_model = nav_model
    if api_key:
        config.api_key = api_key
    if base_url:
        config.base_url = base_url
    config.temperature = temperature
    if service_tier is not None:
        config.service_tier = service_tier
    if reasoning_effort is not None:
        config.reasoning_effort = reasoning_effort
    if verbosity is not None:
        config.verbosity = verbosity
    if nav_reasoning_effort is not None:
        config.navigation_reasoning_effort = nav_reasoning_effort
    if nav_verbosity is not None:
        config.navigation_verbosity = nav_verbosity
    if prompt_cache_retention is not None:
        config.prompt_cache_retention = prompt_cache_retention
    if max_tool_iterations is not None:
        config.max_tool_iterations = max_tool_iterations

    config.normalize()

    if not config.api_key:
        console.print(
            "[red]Error: No API key. Set OPENAI_API_KEY or pass --api-key.[/red]"
        )
        sys.exit(1)

    target_path = str(Path(target).resolve())

    try:
        pipeline = AuditPipeline(target_path, config, output_dir=output)
        report = pipeline.run()

        md_path, json_path = save_report(report, output)

        console.print(f"\n[bold green]{'=' * 60}[/bold green]")
        console.print("[bold green]Audit Complete![/bold green]")
        console.print(f"[bold green]{'=' * 60}[/bold green]")
        console.print(f"\n  Markdown report: [link file://{md_path}]{md_path}[/link]")
        console.print(f"  JSON report:     [link file://{json_path}]{json_path}[/link]")

        confirmed = [i for i in report.issues if i.status.value == "confirmed"]
        console.print(f"\n  Total confirmed findings: [bold]{len(confirmed)}[/bold]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[red]Error: {exc}[/red]")
        raise


@cli.command()
@click.argument("target", type=click.Path(exists=True))
def scan(target: str) -> None:
    """Scan a project and print its structure (no audit)."""
    from .navigator import Navigator

    config = Config.from_env()
    nav = Navigator(str(Path(target).resolve()), config)

    console.print("\n[bold]Project Structure[/bold]\n")
    console.print(nav.get_file_tree())

    files = nav.get_all_file_paths()
    console.print(f"\n[bold]Auditable files ({len(files)}):[/bold]")
    for f in files:
        console.print(f"  {f}")


if __name__ == "__main__":
    cli()
