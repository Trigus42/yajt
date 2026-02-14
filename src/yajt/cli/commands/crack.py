"""hashcat job generation and parsing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...integrations.hashcat_jobs import export_hashcat_job
from ...integrations.hashcat_parse import parse_hashcat_potfile

crack_app = typer.Typer(help="hashcat job generation and parsing")


def _dump_json(value: Any, pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


@crack_app.command("export")
def export_command(
    token: str = typer.Argument(..., help="JWT in compact form"),
    output: Path = typer.Option(..., "--output", "-o", help="Output hash file"),
    mode: int = typer.Option(16500, "--mode", help="Hashcat mode"),
    wordlist: str | None = typer.Option(None, "--wordlist", help="Wordlist path"),
    rules: str | None = typer.Option(None, "--rules", help="Rules file"),
    mask: str | None = typer.Option(None, "--mask", help="Mask pattern"),
    potfile: str | None = typer.Option(None, "--potfile", help="Potfile path"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty JSON output"),
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


@crack_app.command("parse")
def parse_command(
    potfile: Path = typer.Argument(..., help="Hashcat potfile"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty JSON output"),
) -> None:
    entries = parse_hashcat_potfile(potfile)
    _dump_json({"entries": entries}, pretty)
