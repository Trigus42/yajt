"""Normalization helpers for canonicalization."""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..models.jwt_models import JwtParts
from .codec import base64url_encode, json_dumps


def _payload_to_bytes(payload: Any, *, sort_keys: bool = False) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(payload, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def normalize_header_payload(
    header: Mapping[str, Any], payload: Any, *, sort_keys: bool = False
) -> JwtParts:
    header_json = json_dumps(header).encode("utf-8")
    payload_bytes = _payload_to_bytes(payload, sort_keys=sort_keys)
    return JwtParts(
        header_b64=base64url_encode(header_json),
        payload_b64=base64url_encode(payload_bytes),
        signature_b64=None,
    )
