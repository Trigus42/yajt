"""JWS/JWE confusion helpers."""

from __future__ import annotations

from typing import Mapping


def jws_jwe_confusion_headers() -> list[Mapping[str, str]]:
    return [
        {"alg": "none", "enc": "A128GCM"},
        {"alg": "dir", "enc": "A256GCM"},
        {"alg": "RSA-OAEP", "enc": "A256GCM"},
    ]
