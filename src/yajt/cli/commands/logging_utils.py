"""CLI logging helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from ...core.codec import base64url_encode
from ...core.parse import parse_compact_jwt
from ...logging.logbook import LogBook
from ...logging.serializer import append_jsonl
from ...models.evidence import EvidenceItem


def _evidence_item(token_id: str | None, notes: dict[str, Any]) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=str(uuid4()),
        token_id=token_id,
        request=None,
        response=None,
        notes=json.dumps(notes, sort_keys=True, ensure_ascii=True),
    )


def _payload_snapshot(payload: Any) -> Any:
    if isinstance(payload, bytes):
        return {"_bytes_b64": base64url_encode(payload)}
    return payload


def _token_snapshot(token: str) -> dict[str, Any]:
    parsed = parse_compact_jwt(token)
    return {
        "raw": parsed.raw,
        "header": parsed.header,
        "payload": _payload_snapshot(parsed.payload),
        "parts": {
            "header_b64": parsed.parts.header_b64,
            "payload_b64": parsed.parts.payload_b64,
            "signature_b64": parsed.parts.signature_b64,
        },
    }


def write_logbook(path: str | Path, notes: dict[str, Any], token: str | None = None) -> None:
    logbook = LogBook()
    token_id: str | None = None
    if token is not None:
        parsed = parse_compact_jwt(token)
        token_id = logbook.register_token(parsed)
        notes = dict(notes)
        notes["token"] = _token_snapshot(token)

    item = _evidence_item(token_id, notes)
    append_jsonl(path, [item])


def write_logbook_pair(
    path: str | Path,
    notes: dict[str, Any],
    original_token: str,
    new_token: str,
) -> None:
    logbook = LogBook()
    original_id = logbook.register_token(parse_compact_jwt(original_token))
    new_id = logbook.register_token(parse_compact_jwt(new_token))

    payload = dict(notes)
    payload["original_token_id"] = original_id
    payload["new_token_id"] = new_id
    payload["original_token"] = _token_snapshot(original_token)
    payload["new_token"] = _token_snapshot(new_token)

    item = _evidence_item(original_id, payload)
    append_jsonl(path, [item])
