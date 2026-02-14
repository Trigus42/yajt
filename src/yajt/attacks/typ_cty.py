"""typ/cty enforcement gap helpers."""

from __future__ import annotations

from typing import Mapping


def typ_cty_variants(header: Mapping[str, str]) -> list[Mapping[str, str]]:
    variants: list[Mapping[str, str]] = []
    variants.append({"typ": "JWT"})
    variants.append({"typ": "at+jwt"})
    variants.append({"cty": "JWT"})
    variants.append({"cty": "application/jwt"})
    if "typ" in header:
        variants.append({"typ": ""})
    if "cty" in header:
        variants.append({"cty": ""})
    return variants
