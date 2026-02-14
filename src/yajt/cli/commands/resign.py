"""Resign tokens with a supplied key."""

from __future__ import annotations

import typer
from pathlib import Path

from jwcrypto.jwk import JWK

from ...cli.commands.logging_utils import write_logbook_pair
from ...keys.jwk import jwk_from_json, jwk_from_pem
from ...models.log_enums import LogEvent
from ...workflows.resign import resign_token_string


def _load_jwk(jwk: str | None, jwk_file: Path | None, pem_file: Path | None) -> JWK:
    if jwk:
        return jwk_from_json(jwk)
    if jwk_file:
        return jwk_from_json(jwk_file.read_text(encoding="utf-8"))
    if pem_file:
        return jwk_from_pem(pem_file.read_bytes())
    raise typer.BadParameter("Provide --jwk/--jwk-file/--pem")


def resign_command(
    token: str = typer.Argument(..., help="JWT in compact form"),
    alg: str = typer.Option(..., "--alg", help="Signing algorithm"),
    jwk: str | None = typer.Option(None, "--jwk", help="JWK JSON string"),
    jwk_file: Path | None = typer.Option(None, "--jwk-file", help="JWK JSON file"),
    pem_file: Path | None = typer.Option(None, "--pem", help="PEM key file"),
    logbook: str | None = typer.Option(None, "--logbook", help="JSONL logbook path"),
) -> None:
    key = _load_jwk(jwk, jwk_file, pem_file)
    resigned = resign_token_string(token, key, alg)

    if logbook:
        write_logbook_pair(logbook, {"event": LogEvent.RESIGN.value, "alg": alg}, token, resigned)

    typer.echo(resigned)
