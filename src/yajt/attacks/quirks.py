"""Parsing quirk helpers."""

from __future__ import annotations

from typing import Mapping


def base64url_padding_variants(segment: str) -> list[str]:
    variants = {segment}
    variants.add(f"{segment}=")
    variants.add(f"{segment}==")
    variants.add(segment.rstrip("=") or segment)
    return list(variants)


def duplicate_header_variants(header: Mapping[str, str]) -> list[Mapping[str, str]]:
    variants: list[Mapping[str, str]] = []
    for key, value in header.items():
        variants.append({key: value, key.upper(): value})
    return variants
