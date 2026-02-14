"""Signature verification helpers using jwcrypto."""

from __future__ import annotations

from jwcrypto import jws
from jwcrypto.jwk import JWK

from ..models.results import VerifyResult


def verify_compact_jws(token: str, key: JWK) -> VerifyResult:
    verifier = jws.JWS()
    try:
        verifier.deserialize(token)
        verifier.verify(key)
    except Exception as exc:
        return VerifyResult(is_valid=False, alg=None, errors=[str(exc)], warnings=[])

    header = verifier.jose_header
    alg = header.get("alg") if isinstance(header, dict) else None
    return VerifyResult(is_valid=True, alg=alg, errors=[], warnings=[])
