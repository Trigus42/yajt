"""Validation helpers for JWT structure and claims."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ..models.results import ValidationResult
from ..services.policy import ClaimPolicy, _normalize_audience
from .codec import base64url_decode, json_loads
from .parse import split_compact_jwt


def validate_structure(token: str) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        parts = split_compact_jwt(token)
    except ValueError as exc:
        return ValidationResult(is_valid=False, errors=[str(exc)], warnings=warnings)

    try:
        header_bytes = base64url_decode(parts.header_b64)
        header = json_loads(header_bytes)
        if not isinstance(header, Mapping):
            errors.append("Header is not a JSON object")
        else:
            warnings.extend(_header_warnings(header))
    except Exception as exc:
        errors.append(f"Invalid header encoding: {exc}")

    try:
        payload_bytes = base64url_decode(parts.payload_b64)
        json_loads(payload_bytes)
    except Exception:
        warnings.append("Payload is not valid JSON")

    if parts.signature_b64 is not None:
        try:
            base64url_decode(parts.signature_b64)
        except Exception as exc:
            errors.append(f"Invalid signature encoding: {exc}")

    return ValidationResult(is_valid=not errors, errors=errors, warnings=warnings)


def _header_warnings(header: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    typ = header.get("typ")
    if typ is not None:
        if not isinstance(typ, str) or not typ.strip():
            warnings.append("typ header is not a non-empty string")
        elif typ not in {"JWT", "at+jwt", "application/jwt"}:
            warnings.append(f"typ header is unexpected: {typ}")

    cty = header.get("cty")
    if cty is not None:
        if not isinstance(cty, str) or not cty.strip():
            warnings.append("cty header is not a non-empty string")
        elif cty not in {"JWT", "application/jwt"}:
            warnings.append(f"cty header is unexpected: {cty}")

    crit = header.get("crit")
    if crit is not None:
        if not isinstance(crit, list) or not all(isinstance(item, str) for item in crit):
            warnings.append("crit header is not a list of strings")
        else:
            warnings.append(f"crit header present: {', '.join(crit)}")

    return warnings


def _get_claim(payload: Mapping[str, Any], claim: str) -> Any:
    return payload.get(claim)


def validate_claims(
    payload: Any,
    policy: ClaimPolicy,
    now: datetime | None = None,
) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(payload, Mapping):
        return ValidationResult(is_valid=True, errors=errors, warnings=["Payload is not a JSON object"])

    now = now or datetime.now(timezone.utc)
    skew = policy.clock_skew_seconds

    exp = _get_claim(payload, "exp")
    if exp is not None and isinstance(exp, (int, float)):
        if now.timestamp() > exp + skew:
            errors.append("Token is expired")

    nbf = _get_claim(payload, "nbf")
    if nbf is not None and isinstance(nbf, (int, float)):
        if now.timestamp() < nbf - skew:
            errors.append("Token is not yet valid")

    iat = _get_claim(payload, "iat")
    if iat is not None and isinstance(iat, (int, float)):
        if now.timestamp() + skew < iat:
            warnings.append("Issued-at time is in the future")

    if policy.issuer:
        iss = _get_claim(payload, "iss")
        if iss != policy.issuer:
            errors.append("Issuer does not match")

    if policy.audience:
        aud = _get_claim(payload, "aud")
        if aud is None:
            errors.append("Audience is missing")
        else:
            expected = _normalize_audience(policy.audience)
            actual = _normalize_audience(aud)
            if not expected.intersection(actual):
                errors.append("Audience does not match")

    return ValidationResult(is_valid=not errors, errors=errors, warnings=warnings)
