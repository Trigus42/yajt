"""Verification workflows."""

from __future__ import annotations

from typing import Any

from jwcrypto.jwk import JWK, JWKSet

from ..core.parse import parse_compact_jwt
from ..core.validate import validate_claims
from ..core.verify import verify_compact_jws
from ..models.results import ValidationResult, VerifyResult
from ..services.policy import ClaimPolicy
from ..keys.jwks_cache import jwks_select_key


def verify_with_key(token: str, key: JWK) -> VerifyResult:
    return verify_compact_jws(token, key)


def verify_with_jwks(token: str, jwks: JWKSet, kid: str | None = None) -> VerifyResult:
    key = jwks_select_key(jwks, kid)
    if not key:
        return VerifyResult(is_valid=False, alg=None, errors=["No matching key"], warnings=[])
    return verify_compact_jws(token, key)


def verify_and_validate(
    token: str,
    key: JWK | JWKSet,
    *,
    kid: str | None = None,
    policy: ClaimPolicy | None = None,
) -> tuple[VerifyResult, ValidationResult]:
    verify_result: VerifyResult
    if isinstance(key, JWKSet):
        verify_result = verify_with_jwks(token, key, kid=kid)
    else:
        verify_result = verify_with_key(token, key)

    parsed = parse_compact_jwt(token)
    policy = policy or ClaimPolicy()
    claims_result = validate_claims(parsed.payload, policy)
    return verify_result, claims_result
