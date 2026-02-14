"""Error-forcing token variants."""

from __future__ import annotations


def malformed_variants(token: str) -> list[str]:
    parts = token.split(".")
    header = parts[0] if parts else ""
    payload = parts[1] if len(parts) > 1 else ""
    signature = parts[2] if len(parts) > 2 else ""

    variants = [
        "",
        ".",
        "..",
        "a..b",
        "a.b.c.d",
        f"{header}.{payload}",
        f"{header}..{signature}",
        f"@@@.{payload}.{signature}",
        f"{header}.@@@.{signature}",
        f"{header}.{payload}.@@@",
    ]

    return variants
