"""Base64url and JSON helpers."""

from __future__ import annotations

import base64
import json
from typing import Any


def _add_padding(b64: str) -> str:
    padding = (-len(b64)) % 4
    if padding:
        return f"{b64}{'=' * padding}"
    return b64


def base64url_decode(b64: str) -> bytes:
    padded = _add_padding(b64.replace("-", "+").replace("_", "/"))
    return base64.b64decode(padded, validate=True)


def base64url_encode(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(data).rstrip(b"=")
    return encoded.decode("ascii")


def json_loads(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
