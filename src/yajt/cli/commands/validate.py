"""Validate JWT structure and claims."""

from __future__ import annotations

import json
from typing import Any

import typer

from ...core.parse import parse_compact_jwt
from ...core.validate import validate_claims, validate_structure
from ...models.results import ValidationResult
from ...services.policy import ClaimPolicy


def _merge_results(*results: ValidationResult) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    is_valid = True

    for result in results:
        is_valid = is_valid and result.is_valid
        errors.extend(result.errors)
        warnings.extend(result.warnings)

    return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)


def _result_to_dict(result: ValidationResult) -> dict[str, Any]:
    return {
        "is_valid": result.is_valid,
        "errors": result.errors,
        "warnings": result.warnings,
    }


def validate_command(
    token: str = typer.Argument(..., help="JWT in compact form"),
    issuer: str | None = typer.Option(None, "--issuer", "-i", help="Expected issuer"),
    audience: list[str] | None = typer.Option(
        None, "--audience", "-a", help="Expected audience (repeatable)"
    ),
    skew: int = typer.Option(0, "--skew", help="Clock skew in seconds"),
    claims: bool = typer.Option(False, "--claims", help="Validate registered claims"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty JSON output"),
) -> None:
    structure = validate_structure(token)
    results = [structure]

    if claims or issuer or audience or skew:
        parsed = parse_compact_jwt(token)
        policy = ClaimPolicy(issuer=issuer, audience=audience, clock_skew_seconds=skew)
        results.append(validate_claims(parsed.payload, policy))

    merged = _merge_results(*results)
    output = _result_to_dict(merged)

    if pretty:
        typer.echo(json.dumps(output, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(output, separators=(",", ":"), sort_keys=True, ensure_ascii=True))
