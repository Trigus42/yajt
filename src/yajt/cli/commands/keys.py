"""Key and JWK utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import typer
from jwcrypto.jwk import JWK

from ...keys.generate import generate_ec_keypair, generate_rsa_keypair
from ...keys.jwk import jwk_from_json, jwk_from_pem, jwk_to_public
from ...keys.jwks_cache import jwks_from_json, jwks_select_key
from ...models.keys import KeyUse

keys_app = typer.Typer(
    help="Generate keys, convert PEM to JWK, and select from JWKS.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)


def _dump_json(value: Mapping[str, Any], pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


def _parse_use(use: str | None) -> KeyUse | None:
    if not use:
        return None
    value = use.lower()
    if value == "sig":
        return KeyUse.SIG
    if value == "enc":
        return KeyUse.ENC
    raise typer.BadParameter("use must be 'sig' or 'enc'")


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _load_json_input(jwk_json: str | None, file: Path | None) -> Mapping[str, Any] | str:
    if jwk_json:
        return jwk_json
    if file:
        return _read_text(file)
    raise typer.BadParameter("Provide --jwk or --file")


def _export_key(key: JWK, public_only: bool) -> Mapping[str, Any]:
    if public_only:
        return key.export_public(as_dict=True)
    return key.export(as_dict=True)


@keys_app.command("generate-rsa", help="Generate an RSA key pair and output as JWK.")
def generate_rsa_command(
    bits: int = typer.Option(2048, "--bits", "-b", help="RSA key size in bits."),
    kid: str | None = typer.Option(None, "--kid", "-k", help="Key ID to set on the JWK."),
    use: str | None = typer.Option(None, "--use", "-u", help="Key use: sig or enc."),
    alg: str | None = typer.Option(None, "--alg", help="Algorithm hint (e.g. RS256)."),
    public: bool = typer.Option(False, "--public", help="Export public key only."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    key = generate_rsa_keypair(bits=bits, kid=kid, use=_parse_use(use), alg=alg)
    _dump_json(_export_key(key, public), pretty)


@keys_app.command("generate-ec", help="Generate an EC key pair and output as JWK.")
def generate_ec_command(
    curve: str = typer.Option("P-256", "--curve", "-C", help="EC curve name (P-256, P-384, P-521)."),
    kid: str | None = typer.Option(None, "--kid", "-k", help="Key ID to set on the JWK."),
    use: str | None = typer.Option(None, "--use", "-u", help="Key use: sig or enc."),
    alg: str | None = typer.Option(None, "--alg", help="Algorithm hint (e.g. ES256)."),
    public: bool = typer.Option(False, "--public", help="Export public key only."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    key = generate_ec_keypair(curve=curve, kid=kid, use=_parse_use(use), alg=alg)
    _dump_json(_export_key(key, public), pretty)


@keys_app.command("from-pem", help="Import a PEM key file and output as JWK.")
def from_pem_command(
    pem_file: Path = typer.Argument(..., help="Path to PEM key file."),
    password: str | None = typer.Option(None, "--password", help="Password for encrypted PEM."),
    kid: str | None = typer.Option(None, "--kid", "-k", help="Key ID to set on the JWK."),
    use: str | None = typer.Option(None, "--use", "-u", help="Key use: sig or enc."),
    alg: str | None = typer.Option(None, "--alg", help="Algorithm hint."),
    public: bool = typer.Option(False, "--public", help="Export public key only."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    pem_bytes = pem_file.read_bytes()
    password_bytes = password.encode("utf-8") if password else None
    key = jwk_from_pem(pem_bytes, password=password_bytes, kid=kid, use=_parse_use(use), alg=alg)
    _dump_json(_export_key(key, public), pretty)


@keys_app.command("public", help="Extract the public key from a JWK.")
def public_command(
    jwk: str | None = typer.Option(None, "--jwk", help="JWK as a JSON string."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to JWK JSON file."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    data = _load_json_input(jwk, file)
    key = jwk_from_json(data)
    public = jwk_to_public(key)
    _dump_json(public.export_public(as_dict=True), pretty)


@keys_app.command("jwks-select", help="Select a key from a JWKS by key ID.")
def jwks_select_command(
    jwks: str | None = typer.Option(None, "--jwks", help="JWKS as a JSON string."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to JWKS JSON file."),
    kid: str | None = typer.Option(None, "--kid", "-k", help="Key ID to select from set."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    data = _load_json_input(jwks, file)
    jwks_set = jwks_from_json(data)
    key = jwks_select_key(jwks_set, kid)
    if not key:
        raise typer.Exit(code=2)
    _dump_json(key.export_public(as_dict=True), pretty)
