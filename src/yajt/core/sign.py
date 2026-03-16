"""Signing utilities using jwcrypto."""

from __future__ import annotations

import json
from typing import Any, Mapping

from jwcrypto import jws
from jwcrypto.jwk import JWK

from ..models.jwt_models import JwtToken
from .codec import json_dumps
from .normalize import _payload_to_bytes


def sign_compact_jws(
    header: Mapping[str, Any],
    payload: Any,
    key: JWK,
    alg: str,
    *,
    sort_keys: bool = False,
) -> str:
    protected = dict(header)
    protected.setdefault("alg", alg)
    protected_json = json.dumps(protected, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    signer = jws.JWS(payload=_payload_to_bytes(payload, sort_keys=sort_keys))
    signer.add_signature(key, protected=protected_json)
    return signer.serialize(compact=True)


def resign_token(
    token: JwtToken, key: JWK, alg: str, *, sort_keys: bool = False
) -> str:
    return sign_compact_jws(token.header, token.payload, key, alg, sort_keys=sort_keys)
