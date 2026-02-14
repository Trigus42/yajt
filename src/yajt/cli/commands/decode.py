"""Decode and inspect a JWT."""

from __future__ import annotations

import json
from typing import Any, Mapping

import typer

from ...core.codec import base64url_encode
from ...core.parse import parse_compact_jwt


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, bytes):
        return {"_bytes_b64": base64url_encode(value)}
    return value


def decode_command(
    token: str = typer.Argument(..., help="JWT in compact form"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty JSON output"),
) -> None:
    parsed = parse_compact_jwt(token)
    payload = _jsonable(parsed.payload)
    output = {
        "header": _jsonable(parsed.header),
        "payload": payload,
        "parts": {
            "header_b64": parsed.parts.header_b64,
            "payload_b64": parsed.parts.payload_b64,
            "signature_b64": parsed.parts.signature_b64,
        },
    }

    if pretty:
        typer.echo(json.dumps(output, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(output, separators=(",", ":"), sort_keys=True, ensure_ascii=True))
