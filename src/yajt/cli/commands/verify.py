"""Verify JWT signatures and claims."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from jwcrypto.jwk import JWK, JWKSet

from ...cli.commands.logging_utils import write_logbook
from ...keys.jwk import jwk_from_json, jwk_from_pem
from ...keys.jwks_cache import JwksCache, get_cached_jwks, jwks_from_json
from ...models.log_enums import LogEvent
from ...services.policy import ClaimPolicy
from ...workflows.verify import verify_and_validate


def _load_jwk(jwk: str | None, jwk_file: Path | None, pem_file: Path | None) -> JWK | None:
    if jwk:
        return jwk_from_json(jwk)
    if jwk_file:
        return jwk_from_json(jwk_file.read_text(encoding="utf-8"))
    if pem_file:
        return jwk_from_pem(pem_file.read_bytes())
    return None


def _load_jwks(jwks: str | None, jwks_file: Path | None) -> JWKSet | None:
    if jwks:
        return jwks_from_json(jwks)
    if jwks_file:
        return jwks_from_json(jwks_file.read_text(encoding="utf-8"))
    return None


def _dump_json(value: dict[str, Any], pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


def verify_command(
    token: str = typer.Argument(..., help="JWT in compact serialization form."),
    jwk: str | None = typer.Option(None, "--jwk", help="JWK as a JSON string."),
    jwk_file: Path | None = typer.Option(None, "--jwk-file", help="Path to JWK JSON file."),
    jwks: str | None = typer.Option(None, "--jwks", help="JWKS as a JSON string."),
    jwks_file: Path | None = typer.Option(None, "--jwks-file", help="Path to JWKS JSON file."),
    jwks_url: str | None = typer.Option(None, "--jwks-url", help="URL to fetch JWKS from."),
    jwks_ttl: int = typer.Option(300, "--jwks-ttl", help="JWKS cache TTL in seconds."),
    jwks_timeout: float = typer.Option(5.0, "--jwks-timeout", help="JWKS fetch timeout in seconds."),
    pem_file: Path | None = typer.Option(None, "--pem", "-p", help="Path to PEM key file."),
    kid: str | None = typer.Option(None, "--kid", "-k", help="Key ID to select from JWKS."),
    issuer: str | None = typer.Option(None, "--issuer", "-i", help="Expected issuer claim."),
    audience: list[str] | None = typer.Option(
        None, "--audience", "-a", help="Expected audience (repeatable)."
    ),
    skew: int = typer.Option(0, "--skew", "-s", help="Clock skew tolerance in seconds."),
    claims: bool = typer.Option(False, "--claims", "-c", help="Also validate registered claims (exp, nbf, iat)."),
    logbook: str | None = typer.Option(None, "--logbook", "-l", help="Path to JSONL logbook file."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    key = _load_jwk(jwk, jwk_file, pem_file)
    jwks_set = _load_jwks(jwks, jwks_file)
    jwks_warnings: list[str] = []

    if jwks_url:
        cache = JwksCache()
        jwks_set, jwks_warnings = get_cached_jwks(cache, jwks_url, jwks_ttl, jwks_timeout)

    if key and jwks_set:
        raise typer.BadParameter("Provide a single key source")
    if not key and not jwks_set:
        raise typer.BadParameter(
            "Provide --jwk/--jwk-file/--pem or --jwks/--jwks-file/--jwks-url"
        )

    policy = ClaimPolicy(issuer=issuer, audience=audience, clock_skew_seconds=skew)
    verify_result, claims_result = verify_and_validate(
        token,
        key if key else jwks_set,
        kid=kid,
        policy=policy if claims or issuer or audience or skew else ClaimPolicy(),
    )

    output = {
        "verify": {
            "is_valid": verify_result.is_valid,
            "alg": verify_result.alg,
            "errors": verify_result.errors,
            "warnings": verify_result.warnings,
        },
        "claims": {
            "is_valid": claims_result.is_valid,
            "errors": claims_result.errors,
            "warnings": claims_result.warnings,
        },
        "jwks": {"warnings": jwks_warnings},
    }

    if logbook:
        write_logbook(
            logbook,
            {
                "event": LogEvent.VERIFY.value,
                "verify": output["verify"],
                "claims": output["claims"],
                "jwks": output["jwks"],
            },
            token=token,
        )

    _dump_json(output, pretty)
