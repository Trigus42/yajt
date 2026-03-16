"""Tests for the edit command."""

from __future__ import annotations

from typer.testing import CliRunner

from yajt.cli.app import app
from yajt.core.codec import base64url_decode

runner = CliRunner()


def test_edit_from_scratch_with_header_and_payload() -> None:
    result = runner.invoke(app, [
        "edit",
        "-H", '{"alg":"HS256","typ":"JWT"}',
        "-P", '{"sub":"test"}',
    ])
    assert result.exit_code == 0
    output = result.output.strip()
    parts = output.split(".")
    assert len(parts) == 2
    header = base64url_decode(parts[0]).decode()
    payload = base64url_decode(parts[1]).decode()
    assert '"alg":"HS256"' in header
    assert '"sub":"test"' in payload


def test_edit_from_scratch_no_signature() -> None:
    result = runner.invoke(app, [
        "edit",
        "-H", '{"alg":"none"}',
        "-P", '{"admin":true}',
    ])
    assert result.exit_code == 0
    output = result.output.strip()
    # No signature segment
    assert len(output.split(".")) == 2


def test_edit_existing_token() -> None:
    # Minimal HS256 token with {"sub":"original"}
    result = runner.invoke(app, [
        "edit",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcmlnaW5hbCJ9",
        "-H", '{"alg":"HS256"}',
        "-P", '{"sub":"modified"}',
    ])
    assert result.exit_code == 0
    payload = base64url_decode(result.output.strip().split(".")[1]).decode()
    assert '"sub":"modified"' in payload


def test_edit_from_scratch_preserves_payload_order() -> None:
    result = runner.invoke(app, [
        "edit",
        "-H", '{"alg":"HS256"}',
        "-P", '{"z":1,"a":2,"m":3}',
    ])
    assert result.exit_code == 0
    payload = base64url_decode(result.output.strip().split(".")[1]).decode()
    assert payload == '{"z":1,"a":2,"m":3}'


def test_edit_from_scratch_sort_keys() -> None:
    result = runner.invoke(app, [
        "edit",
        "-H", '{"alg":"HS256"}',
        "-P", '{"z":1,"a":2,"m":3}',
        "--sort-keys",
    ])
    assert result.exit_code == 0
    payload = base64url_decode(result.output.strip().split(".")[1]).decode()
    assert payload == '{"a":2,"m":3,"z":1}'
