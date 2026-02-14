"""Claim injection workflow helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..attacks.claim_injection import load_claim_injections
from ..attacks.variants import mutate_compact_token
from ..core.parse import parse_compact_jwt
from ..models.attack_enums import AttackReason


@dataclass(frozen=True, slots=True)
class ClaimInjectionVariant:
    variant_id: str
    claim: str
    token: str
    value: str
    reason: AttackReason


def claim_injection_variants(token: str, claim_wordlists: Mapping[str, str]) -> list[ClaimInjectionVariant]:
    parsed = parse_compact_jwt(token)
    if not isinstance(parsed.payload, Mapping):
        raise ValueError("Payload is not a JSON object; cannot inject claims")

    variants: list[ClaimInjectionVariant] = []
    for claim, path in claim_wordlists.items():
        injected_payloads = load_claim_injections(parsed.payload, claim, path)
        for index, payload in enumerate(injected_payloads, start=1):
            mutated = mutate_compact_token(token, payload_updates=payload, keep_signature=True)
            value = payload.get(claim)
            variants.append(
                ClaimInjectionVariant(
                    variant_id=f"{AttackReason.CLAIM_INJECTION.value}-{claim}-{index}",
                    claim=claim,
                    token=mutated,
                    value=str(value),
                    reason=AttackReason.CLAIM_INJECTION,
                )
            )

    return variants


def claim_injection_value_variants(
    token: str,
    claim_values: Mapping[str, list[str]],
) -> list[ClaimInjectionVariant]:
    parsed = parse_compact_jwt(token)
    if not isinstance(parsed.payload, Mapping):
        raise ValueError("Payload is not a JSON object; cannot inject claims")

    variants: list[ClaimInjectionVariant] = []
    for claim, values in claim_values.items():
        for index, value in enumerate(values, start=1):
            payload = dict(parsed.payload)
            payload[claim] = value
            mutated = mutate_compact_token(token, payload_updates=payload, keep_signature=True)
            variants.append(
                ClaimInjectionVariant(
                    variant_id=f"{AttackReason.CLAIM_INJECTION.value}-{claim}-{index}",
                    claim=claim,
                    token=mutated,
                    value=str(value),
                    reason=AttackReason.CLAIM_INJECTION,
                )
            )

    return variants
