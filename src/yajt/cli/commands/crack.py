"""hashcat job generation and parsing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...integrations.hashcat_jobs import export_hashcat_job
from ...integrations.hashcat_parse import parse_hashcat_potfile

crack_app = typer.Typer(
    help="Export hashcat cracking jobs and parse potfiles.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)


def _dump_json(value: Any, pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


@crack_app.command("export", help="Export a hashcat cracking job for HMAC-signed JWTs.")
def export_command(
    token: str = typer.Argument(..., help="JWT in compact serialization form."),
    output: Path = typer.Option(..., "--output", "-o", help="Output hash file path."),
    mode: int = typer.Option(16500, "--mode", "-m", help="Hashcat attack mode."),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="Path to wordlist file."),
    rules: str | None = typer.Option(None, "--rules", "-r", help="Path to hashcat rules file."),
    mask: str | None = typer.Option(None, "--mask", help="Mask pattern for brute-force."),
    potfile: str | None = typer.Option(None, "--potfile", help="Path to potfile."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    job = export_hashcat_job(
        token,
        output,
        mode=mode,
        wordlist=wordlist,
        rules=rules,
        mask=mask,
        potfile=potfile,
    )
    _dump_json(job.to_dict(), pretty)


@crack_app.command("parse", help="Parse a hashcat potfile and extract recovered secrets.")
def parse_command(
    potfile: Path = typer.Argument(..., help="Path to hashcat potfile."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    entries = parse_hashcat_potfile(potfile)
    _dump_json({"entries": entries}, pretty)
