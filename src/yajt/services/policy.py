"""Policy helpers for claim validation and algorithms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class ClaimPolicy:
    issuer: str | None = None
    audience: str | Sequence[str] | None = None
    clock_skew_seconds: int = 0


def _normalize_audience(audience: str | Sequence[str] | Iterable[str]) -> set[str]:
    if isinstance(audience, str):
        return {audience}
    return {item for item in audience if isinstance(item, str)}
