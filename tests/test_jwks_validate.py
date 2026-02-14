from __future__ import annotations

from jwcrypto.jwk import JWK, JWKSet

from yajt.keys.jwks_cache import jwks_validate


def test_jwks_validate_warns_on_drift() -> None:
    key_a = JWK.generate(kty="RSA", size=1024)
    key_a.update(kid="a", alg="RS256", use="sig")
    key_b = JWK.generate(kty="RSA", size=1024)
    key_b.update(kid="b", alg="RS512", use="sig")

    jwks = JWKSet()
    jwks.add(key_a)
    jwks.add(key_b)

    warnings = jwks_validate(jwks)
    assert any("multiple alg" in warning for warning in warnings)
