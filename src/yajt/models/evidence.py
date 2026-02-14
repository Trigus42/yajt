"""Evidence and request/response metadata models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestMeta:
    method: str | None
    url: str | None
    headers: dict[str, str] | None
    body: bytes | None


@dataclass(frozen=True, slots=True)
class ResponseMeta:
    status_code: int | None
    headers: dict[str, str] | None
    body: bytes | None


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    evidence_id: str
    token_id: str | None
    request: RequestMeta | None
    response: ResponseMeta | None
    notes: str | None
