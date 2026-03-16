"""Interactive JWT editor."""

from __future__ import annotations

import json
from typing import Any, Mapping

import typer

from ...core.codec import base64url_decode, base64url_encode, json_dumps
from ...core.normalize import normalize_header_payload
from ...core.parse import parse_compact_jwt


def _prompt_json(prompt: str, default: str) -> str:
    return typer.prompt(prompt, default=default)


def _parse_header_input(value: str) -> Mapping[str, Any]:
    data = json.loads(value)
    if not isinstance(data, Mapping):
        raise typer.BadParameter("Header JSON must be an object")
    return data


def _parse_payload_input(value: str) -> Any:
    if value.startswith("b64:"):
        decoded = base64url_decode(value[4:])
        return decoded
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def edit_command(
    token: str = typer.Argument(..., help="JWT in compact serialization form."),
    header: str | None = typer.Option(None, "--header", "-H", help="New header as JSON string."),
    payload: str | None = typer.Option(None, "--payload", "-P", help="New payload as JSON, plain string, or b64:... encoded."),
    keep_signature: bool = typer.Option(
        False, "--keep-signature", "-K", help="Keep the original signature intact."
    ),
) -> None:
    parsed = parse_compact_jwt(token)
    default_header = json_dumps(parsed.header)

    if isinstance(parsed.payload, Mapping):
        default_payload = json_dumps(parsed.payload)
    elif isinstance(parsed.payload, bytes):
        default_payload = f"b64:{base64url_encode(parsed.payload)}"
    else:
        default_payload = str(parsed.payload)

    header_input = header or _prompt_json("Header JSON", default_header)
    payload_input = payload or _prompt_json("Payload JSON", default_payload)

    new_header = _parse_header_input(header_input)
    new_payload = _parse_payload_input(payload_input)

    normalized = normalize_header_payload(new_header, new_payload)
    if keep_signature and parsed.parts.signature_b64:
        typer.echo(
            f"{normalized.header_b64}.{normalized.payload_b64}.{parsed.parts.signature_b64}"
        )
        return

    typer.echo(f"{normalized.header_b64}.{normalized.payload_b64}")
