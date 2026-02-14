"""Standard JWT claims and typed claim containers."""

from __future__ import annotations

from enum import StrEnum
from typing import NotRequired, TypedDict


class RegisteredClaim(StrEnum):
    ISS = "iss"
    SUB = "sub"
    AUD = "aud"
    EXP = "exp"
    NBF = "nbf"
    IAT = "iat"
    JTI = "jti"


class RegisteredClaims(TypedDict, total=False):
    iss: str
    sub: str
    aud: str | list[str]
    exp: int
    nbf: int
    iat: int
    jti: str
    typ: NotRequired[str]
    cty: NotRequired[str]
