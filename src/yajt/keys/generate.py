"""Key generation helpers."""

from __future__ import annotations

from jwcrypto.jwk import JWK

from ..models.keys import KeyType, KeyUse


def _apply_metadata(key: JWK, kid: str | None, use: KeyUse | None, alg: str | None) -> JWK:
    if kid:
        key.update(kid=kid)
    if use:
        key.update(use=use.value)
    if alg:
        key.update(alg=alg)
    return key


def generate_rsa_keypair(
    bits: int = 2048,
    *,
    kid: str | None = None,
    use: KeyUse | None = KeyUse.SIG,
    alg: str | None = None,
) -> JWK:
    key = JWK.generate(kty=KeyType.RSA.value, size=bits)
    return _apply_metadata(key, kid, use, alg)


def generate_ec_keypair(
    curve: str = "P-256",
    *,
    kid: str | None = None,
    use: KeyUse | None = KeyUse.SIG,
    alg: str | None = None,
) -> JWK:
    key = JWK.generate(kty=KeyType.EC.value, crv=curve)
    return _apply_metadata(key, kid, use, alg)
