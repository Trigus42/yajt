"""Stable token ID generation."""

from __future__ import annotations

import hashlib

from ..models.jwt_models import JwtParts


def token_id(parts: JwtParts) -> str:
    material = ".".join(filter(None, [parts.header_b64, parts.payload_b64, parts.signature_b64 or ""]))
    return hashlib.sha256(material.encode("ascii")).hexdigest()
