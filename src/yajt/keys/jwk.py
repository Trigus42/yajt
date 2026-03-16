"""JWK import/export helpers."""

from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from jwcrypto.jwk import JWK

from ..models.keys import KeyMaterial, KeyType, KeyUse


def jwk_from_secret(secret: bytes | str) -> JWK:
    """Create an oct JWK from raw HMAC key material."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    k = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
    return JWK(**{"kty": "oct", "k": k})


def jwk_from_pem(
    pem: str | bytes,
    *,
    password: bytes | None = None,
    kid: str | None = None,
    use: KeyUse | None = None,
    alg: str | None = None,
) -> JWK:
    if isinstance(pem, str):
        pem_bytes = pem.encode("utf-8")
    else:
        pem_bytes = pem

    key = JWK.from_pem(pem_bytes, password=password)
    if kid:
        key.update(kid=kid)
    if use:
        key.update(use=use.value)
    if alg:
        key.update(alg=alg)
    return key


def jwk_from_json(jwk_data: str | Mapping[str, Any]) -> JWK:
    if isinstance(jwk_data, str):
        return JWK.from_json(jwk_data)
    return JWK.from_json(json.dumps(jwk_data))


def jwk_to_public(key: JWK) -> JWK:
    public_json = key.export_public(as_dict=True)
    return JWK.from_json(json.dumps(public_json))


def key_material_from_jwk(key: JWK) -> KeyMaterial:
    data = key.export(as_dict=True)
    kty_value = data.get("kty")
    use_value = data.get("use")
    alg = data.get("alg")
    kid = data.get("kid")

    kty = KeyType(kty_value) if kty_value in KeyType._value2member_map_ else KeyType.OCT
    use = KeyUse(use_value) if use_value in KeyUse._value2member_map_ else None

    return KeyMaterial(kid=kid, kty=kty, use=use, alg=alg, key=key)
