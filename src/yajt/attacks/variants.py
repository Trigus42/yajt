"""JWT variant helpers."""

from __future__ import annotations

from typing import Any, Mapping

from ..core.normalize import normalize_header_payload
from ..core.parse import parse_compact_jwt


def _merge_mapping(base: Mapping[str, Any], updates: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = dict(base)
    if updates:
        merged.update(updates)
    return merged


def mutate_compact_token(
    token: str,
    *,
    header_updates: Mapping[str, Any] | None = None,
    payload_updates: Mapping[str, Any] | None = None,
    keep_signature: bool = False,
    drop_signature: bool = False,
) -> str:
    parsed = parse_compact_jwt(token)

    if payload_updates and not isinstance(parsed.payload, Mapping):
        raise ValueError("Payload is not a JSON object; cannot apply payload updates")

    header = _merge_mapping(parsed.header, header_updates)
    payload: Any = parsed.payload
    if payload_updates:
        payload = _merge_mapping(parsed.payload, payload_updates)

    normalized = normalize_header_payload(header, payload)
    signature_b64 = None

    if keep_signature and parsed.parts.signature_b64:
        signature_b64 = parsed.parts.signature_b64
    if drop_signature:
        signature_b64 = None

    if signature_b64 is None:
        return f"{normalized.header_b64}.{normalized.payload_b64}"

    return f"{normalized.header_b64}.{normalized.payload_b64}.{signature_b64}"
