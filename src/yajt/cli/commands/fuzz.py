"""ffuf job generation and parsing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...integrations.ffuf_jobs import (
    body_injection_job,
    cookie_injection_job,
    export_ffuf_job,
    header_injection_job,
    query_injection_job,
)
from ...integrations.ffuf_parse import parse_ffuf_csv, parse_ffuf_json

fuzz_app = typer.Typer(
    help="Export ffuf fuzzing jobs and parse results.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)


def _dump_json(value: Any, pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


@fuzz_app.command("export", help="Generate an ffuf fuzzing job configuration.")
def export_command(
    url: str = typer.Argument(..., help="Target URL to fuzz."),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Path to wordlist file."),
    mode: str = typer.Option(
        "header", "--mode", "-m", help="Injection mode: header, cookie, query, or body."
    ),
    name: str = typer.Option(..., "--name", "-n", help="Header, cookie, or parameter name."),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON file path."),
    method: str = typer.Option("GET", "--method", help="HTTP method to use."),
    proxy: str | None = typer.Option(None, "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)."),
    rate: int | None = typer.Option(None, "--rate", "-r", help="Maximum request rate per second."),
) -> None:
    mode_value = mode.lower()
    if mode_value == "header":
        job = header_injection_job(url, name, wordlist, method=method, proxy=proxy, rate=rate)
    elif mode_value == "cookie":
        job = cookie_injection_job(url, name, wordlist, method=method, proxy=proxy, rate=rate)
    elif mode_value == "query":
        job = query_injection_job(url, name, wordlist, method=method, proxy=proxy, rate=rate)
    elif mode_value == "body":
        job = body_injection_job(url, name, wordlist, method=method, proxy=proxy, rate=rate)
    else:
        raise typer.BadParameter("mode must be one of header, cookie, query, body")

    export_ffuf_job(job, output)


@fuzz_app.command("parse", help="Parse ffuf JSON or CSV output into structured results.")
def parse_command(
    input_file: Path = typer.Argument(..., help="Path to ffuf JSON or CSV output file."),
    format: str = typer.Option("json", "--format", "-f", help="Input format: json or csv."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    format_value = format.lower()
    if format_value == "json":
        results = parse_ffuf_json(input_file)
    elif format_value == "csv":
        results = parse_ffuf_csv(input_file)
    else:
        raise typer.BadParameter("format must be json or csv")

    _dump_json({"results": results}, pretty)
