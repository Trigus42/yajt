"""Token data structures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, TypeAlias

JsonMapping: TypeAlias = Mapping[str, Any]
JwtHeader: TypeAlias = JsonMapping
JwtPayload: TypeAlias = JsonMapping | str | bytes


@dataclass(frozen=True, slots=True)
class JwtParts:
    header_b64: str
    payload_b64: str
    signature_b64: str | None


@dataclass(frozen=True, slots=True)
class JwtToken:
    raw: str
    parts: JwtParts
    header: JwtHeader
    payload: JwtPayload
    signature: bytes | None
