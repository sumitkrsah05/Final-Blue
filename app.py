#!/usr/bin/env python3
"""Blue Team Analysis Agent — command-line entry point.

Reads a Red Agent JSON report, runs LLM-backed defensive analysis, and writes
``blue_analysis.json`` plus ``blue_report.md``.

    python app.py --input input/sample_report.json --output output/
    python app.py --input report.json --offline      # no LLM, deterministic
    python app.py --input report.json --provider openai --model gpt-4o

The agent never scans, probes, or contacts any target system; it only reasons
over the report it is handed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from rich.panel import Panel
from rich.table import Table

from config import PROVIDER_OFFLINE, Settings
from models.schemas import BlueAnalysis, Severity
from services.llm import LLMService
from services.parser import ReportParseError, parse_report
from services.report_generator import ReportGenerator
from utils.logger import configure_logging, console, get_logger

log = get_logger("blue_agent")

_RISK_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.UNKNOWN: "dim",
}

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARSE_ERROR = 3
EXIT_RUNTIME_ERROR = 4


def build_arg_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="blue-agent",
        description="AI Blue Team analysis of a Red Agent findings report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input", type=Path, default=None,
        help="Path to the Red Agent JSON report (default: input/sample_report.json).",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Directory for blue_analysis.json and blue_report.md (default: output/).",
    )
    parser.add_argument(
        "--provider", default=None,
        help="LLM backend: modal, openai, vllm, ollama, azure, or offline.",
    )
    parser.add_argument("--model", default=None, help="Model name to request.")
    parser.add_argument("--base-url", default=None, help="Override the LLM endpoint URL.")
    parser.add_argument("--temperature", type=float, default=None, help="Sampling temperature.")
    parser.add_argument("--max-tokens", type=int, default=None, help="Completion token budget.")
    parser.add_argument(
        "--concurrency", type=int, default=None,
        help="Findings analysed in parallel.",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Skip the LLM entirely and use the deterministic heuristic analyser.",
    )
    parser.add_argument(
        "--no-fallback", action="store_true",
        help="Fail the run instead of falling back to heuristics when the LLM errors.",
    )
    parser.add_argument(
        "--log-level", default=None,
        help="DEBUG, INFO, WARNING or ERROR.",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the console summary; only write the output files.",
    )
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    """Merge CLI flags over environment configuration."""
    overrides: dict[str, object] = {
        "input_path": args.input,
        "output_dir": args.output,
        "model_name": args.model,
        "llm_base_url": args.base_url,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "concurrency": args.concurrency,
        "log_level": args.log_level,
    }
    if args.offline:
        overrides["llm_provider"] = PROVIDER_OFFLINE
    elif args.provider:
        overrides["llm_provider"] = args.provider
    if args.no_fallback:
        overrides["allow_offline_fallback"] = False
    return Settings.from_env(**overrides)


def run_analysis(settings: Settings) -> tuple[BlueAnalysis, dict[str, Path]]:
    """Run the full pipeline: parse → analyse → render.

    Args:
        settings: Fully resolved runtime configuration.

    Returns:
        The analysis object and the paths of the written artefacts.

    Raises:
        ReportParseError: The input report could not be read.
    """
    log.info("Reading Red Agent report from {}", settings.input_path)
    report = parse_report(settings.input_path)

    service = LLMService(settings)
    if service.llm_available:
        log.info(
            "Using {} provider, model {} (first call may be slow — Modal cold start)",
            service.provider.name,
            settings.model_name,
        )
    else:
        log.warning("Running without an LLM — analysis will use the heuristic engine")

    analysis = service.generate_report(report)
    paths = ReportGenerator(settings.output_dir).generate(analysis)
    return analysis, paths


def render_console_summary(analysis: BlueAnalysis, paths: dict[str, Path]) -> None:
    """Print a compact result summary to the terminal."""
    risk_style = _RISK_STYLE.get(analysis.overall_risk, "white")
    summary = analysis.summary

    console.print()
    console.print(
        Panel(
            f"[{risk_style}] OVERALL RISK: {analysis.overall_risk.label.upper()} [/]\n\n"
            f"Target        : {analysis.target}\n"
            f"Engagement    : {analysis.engagement_id}\n"
            f"Findings      : {analysis.metadata.findings_analysed} "
            f"({analysis.metadata.llm_analysed} via LLM, "
            f"{analysis.metadata.heuristic_analysed} heuristic)\n"
            f"Peak risk     : {summary.get('max_risk_score', 0)}/10\n"
            f"Immediate acts: {summary.get('immediate_actions', 0)}",
            title="Blue Team Analysis",
            border_style="blue",
        )
    )

    if analysis.findings:
        table = Table(title="Risk Register", header_style="bold blue", show_lines=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Finding", overflow="fold")
        table.add_column("Severity")
        table.add_column("Risk", justify="right")
        table.add_column("Priority")
        for index, finding in enumerate(analysis.findings, start=1):
            table.add_row(
                str(index),
                finding.title[:70],
                f"[{_RISK_STYLE.get(finding.severity, 'white')}]{finding.severity.label}[/]",
                f"{finding.risk_assessment.overall_risk_score}",
                finding.risk_assessment.priority,
            )
        console.print(table)

    top_risks = analysis.executive_summary.top_risks[:3]
    if top_risks:
        console.print("\n[bold]Top risks[/bold]")
        for risk in top_risks:
            console.print(f"  • {risk}")

    console.print("\n[bold]Artefacts[/bold]")
    for label, path in paths.items():
        console.print(f"  • {label}: [green]{path}[/green]")
    console.print()


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_arg_parser().parse_args(argv)
    settings = settings_from_args(args)
    configure_logging(settings.log_level, log_file=settings.output_dir / "blue_agent.log")

    if not Path(settings.input_path).exists():
        log.error("Input report not found: {}", settings.input_path)
        return EXIT_USAGE

    try:
        analysis, paths = run_analysis(settings)
    except ReportParseError as exc:
        log.error("Could not parse the Red Agent report: {}", exc)
        return EXIT_PARSE_ERROR
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        return EXIT_RUNTIME_ERROR
    except Exception as exc:  # noqa: BLE001 - top-level guard for a CLI
        log.exception("Analysis failed: {}", exc)
        return EXIT_RUNTIME_ERROR

    if not args.quiet:
        render_console_summary(analysis, paths)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
