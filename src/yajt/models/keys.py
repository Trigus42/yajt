"""Key and JWK models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, TypeAlias

Jwk: TypeAlias = Mapping[str, Any]
Jwks: TypeAlias = Mapping[str, Any]


class KeyType(StrEnum):
    RSA = "RSA"
    EC = "EC"
    OCT = "oct"


class KeyUse(StrEnum):
    SIG = "sig"
    ENC = "enc"


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    kid: str | None
    kty: KeyType
    use: KeyUse | None
    alg: str | None
    key: Any
