"""KID injection variants."""

from __future__ import annotations

from typing import Iterable


def _with_suffixes(base: str, suffixes: Iterable[str]) -> list[str]:
    return [f"{base}{suffix}" for suffix in suffixes]


def kid_injection_variants(kid: str | None) -> list[str]:
    base = kid or "kid"
    variants: list[str] = []

    variants.extend(_with_suffixes(base, ["..", "../", "../../", "../../../../"]))
    variants.extend(_with_suffixes(base, ["%00", "\u0000"]))
    variants.extend(
        [
            f"file:///etc/passwd",
            f"file://{base}",
            f"http://127.0.0.1/{base}",
            f"http://localhost/{base}",
            f"https://{base}.invalid/.well-known/jwks.json",
        ]
    )
    variants.extend(_with_suffixes(base, ["/../", "..%2f", "%2e%2e%2f"]))

    return variants
