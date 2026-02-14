"""Claim injection helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ..services.wordlists import load_wordlist


def inject_claims(payload: Mapping[str, Any], claims: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(payload)
    merged.update(claims)
    return merged


def batch_inject_claims(
    payload: Mapping[str, Any],
    claim_values: Mapping[str, Sequence[Any]],
) -> list[dict[str, Any]]:
    variants: list[dict[str, Any]] = []
    for claim, values in claim_values.items():
        for value in values:
            variants.append(inject_claims(payload, {claim: value}))
    return variants


def load_claim_injections(
    payload: Mapping[str, Any],
    claim: str,
    wordlist_path: str,
) -> list[dict[str, Any]]:
    values = load_wordlist(wordlist_path)
    return [inject_claims(payload, {claim: value}) for value in values]
