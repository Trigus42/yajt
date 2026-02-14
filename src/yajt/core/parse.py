"""Parsing utilities for compact JWS tokens."""

from __future__ import annotations

from typing import Any, Mapping

from ..models.jwt_models import JwtParts, JwtToken
from .codec import base64url_decode, json_loads


def split_compact_jwt(token: str) -> JwtParts:
    parts = token.split(".")
    if len(parts) == 3:
        return JwtParts(parts[0], parts[1], parts[2])
    if len(parts) == 2:
        return JwtParts(parts[0], parts[1], None)
    raise ValueError("Token must have 2 or 3 segments")


def _decode_segment(segment: str) -> bytes:
    return base64url_decode(segment)


def _parse_json(data: bytes) -> Any:
    return json_loads(data)


def _parse_header(segment: str) -> Mapping[str, Any]:
    data = _decode_segment(segment)
    value = _parse_json(data)
    if not isinstance(value, Mapping):
        raise ValueError("Header must be a JSON object")
    return value


def _parse_payload(segment: str) -> Any:
    data = _decode_segment(segment)
    try:
        return _parse_json(data)
    except Exception:
        return data


def parse_compact_jwt(token: str) -> JwtToken:
    parts = split_compact_jwt(token)
    header = _parse_header(parts.header_b64)
    payload = _parse_payload(parts.payload_b64)
    signature = _decode_segment(parts.signature_b64) if parts.signature_b64 else None
    return JwtToken(raw=token, parts=parts, header=header, payload=payload, signature=signature)
