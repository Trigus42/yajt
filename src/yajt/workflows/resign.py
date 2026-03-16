"""Resigning workflows."""

from __future__ import annotations

from jwcrypto.jwk import JWK

from ..core.parse import parse_compact_jwt
from ..core.sign import resign_token


def resign_token_string(
    token: str, key: JWK, alg: str, *, sort_keys: bool = False
) -> str:
    parsed = parse_compact_jwt(token)
    return resign_token(parsed, key, alg, sort_keys=sort_keys)
