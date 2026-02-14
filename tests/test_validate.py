from __future__ import annotations

from yajt.core.codec import base64url_encode, json_dumps
from yajt.core.validate import validate_structure


def _build_token(header: dict[str, object], payload: dict[str, object]) -> str:
    header_b64 = base64url_encode(json_dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json_dumps(payload).encode("utf-8"))
    return f"{header_b64}.{payload_b64}"


def test_validate_structure_warns_on_typ_cty_crit() -> None:
    token = _build_token(
        {"alg": "HS256", "typ": "weird", "cty": "", "crit": ["exp"]},
        {"sub": "user"},
    )
    result = validate_structure(token)
    assert result.is_valid
    assert any("typ header" in warning for warning in result.warnings)
    assert any("cty header" in warning for warning in result.warnings)
    assert any("crit header present" in warning for warning in result.warnings)
