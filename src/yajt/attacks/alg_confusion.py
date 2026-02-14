"""Algorithm confusion helpers."""

from __future__ import annotations

from typing import Mapping


def alg_hs_rs_confusion_variants(header: Mapping[str, str]) -> list[Mapping[str, str]]:
    alg = header.get("alg", "")
    variants: list[Mapping[str, str]] = []

    if alg.startswith("RS"):
        variants.append({"alg": f"HS{alg[2:]}"})
    if alg.startswith("PS"):
        variants.append({"alg": f"HS{alg[2:]}"})
    if alg.startswith("ES"):
        variants.append({"alg": f"HS{alg[2:]}"})

    return variants


def alg_downgrade_variants(header: Mapping[str, str]) -> list[Mapping[str, str]]:
    variants: list[Mapping[str, str]] = []
    alg = header.get("alg", "")

    if alg and alg != "none":
        variants.append({"alg": "none"})
    if alg.startswith("RS"):
        variants.append({"alg": "RS256"})
    if alg.startswith("ES"):
        variants.append({"alg": "ES256"})
    if alg.startswith("PS"):
        variants.append({"alg": "PS256"})

    return variants
