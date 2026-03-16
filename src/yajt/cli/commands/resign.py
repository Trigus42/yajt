"""Resign tokens with a supplied key."""

from __future__ import annotations

import typer
from pathlib import Path

from jwcrypto.jwk import JWK

from ...cli.commands.logging_utils import write_logbook_pair
from ...keys.jwk import jwk_from_json, jwk_from_pem, jwk_from_secret
from ...models.log_enums import LogEvent
from ...workflows.resign import resign_token_string


def _load_jwk(
    jwk: str | None,
    jwk_file: Path | None,
    pem_file: Path | None,
    secret: str | None,
    secret_file: Path | None,
) -> JWK:
    if jwk:
        return jwk_from_json(jwk)
    if jwk_file:
        return jwk_from_json(jwk_file.read_text(encoding="utf-8"))
    if pem_file:
        return jwk_from_pem(pem_file.read_bytes())
    if secret:
        return jwk_from_secret(secret)
    if secret_file:
        return jwk_from_secret(secret_file.read_bytes())
    raise typer.BadParameter("Provide --jwk/--jwk-file/--pem/--secret/--secret-file")


def resign_command(
    token: str = typer.Argument(..., help="JWT in compact serialization form."),
    alg: str = typer.Option(..., "--alg", "-A", help="Target signing algorithm (e.g. HS256, RS256)."),
    jwk: str | None = typer.Option(None, "--jwk", help="JWK as a JSON string."),
    jwk_file: Path | None = typer.Option(None, "--jwk-file", help="Path to JWK JSON file."),
    pem_file: Path | None = typer.Option(None, "--pem", "-p", help="Path to PEM key file."),
    secret: str | None = typer.Option(None, "--secret", "-s", help="Raw HMAC secret string."),
    secret_file: Path | None = typer.Option(None, "--secret-file", "-S", help="Path to file whose content is the HMAC secret."),
    sort_keys: bool = typer.Option(False, "--sort-keys", help="Sort payload JSON keys alphabetically."),
    logbook: str | None = typer.Option(None, "--logbook", "-l", help="Path to JSONL logbook file."),
) -> None:
    key = _load_jwk(jwk, jwk_file, pem_file, secret, secret_file)
    resigned = resign_token_string(token, key, alg, sort_keys=sort_keys)

    if logbook:
        write_logbook_pair(logbook, {"event": LogEvent.RESIGN.value, "alg": alg}, token, resigned)

    typer.echo(resigned)
