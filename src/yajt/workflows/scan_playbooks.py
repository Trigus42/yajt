"""Scan playbooks for common JWT misconfigurations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..attacks.alg_confusion import alg_downgrade_variants, alg_hs_rs_confusion_variants
from ..attacks.jws_jwe import jws_jwe_confusion_headers
from ..attacks.kid_injection import kid_injection_variants
from ..attacks.quirks import base64url_padding_variants, duplicate_header_variants
from ..attacks.typ_cty import typ_cty_variants
from ..attacks.variants import mutate_compact_token
from ..core.parse import parse_compact_jwt
from ..models.attack_enums import AttackName, AttackReason, B64Variant


@dataclass(frozen=True, slots=True)
class ScanVariant:
    variant_id: str
    token: str
    reason: AttackReason


def _add_header_variants(
    variants: list[ScanVariant],
    token: str,
    updates: list[Mapping[str, Any]],
    reason_prefix: AttackReason,
) -> None:
    for index, update in enumerate(updates, start=1):
        mutated = mutate_compact_token(token, header_updates=update, keep_signature=True)
        variants.append(
            ScanVariant(
                variant_id=f"{reason_prefix.value}-{index}",
                token=mutated,
                reason=reason_prefix,
            )
        )


def attack_variants(
    token: str,
    attack: AttackName,
    *,
    extra_kid: list[str] | None = None,
) -> list[ScanVariant]:
    parsed = parse_compact_jwt(token)
    variants: list[ScanVariant] = []

    if attack == AttackName.ALG_CONFUSION:
        _add_header_variants(
            variants,
            token,
            alg_hs_rs_confusion_variants(parsed.header),
            AttackReason.ALG_CONFUSION,
        )
    elif attack == AttackName.ALG_DOWNGRADE:
        _add_header_variants(
            variants,
            token,
            alg_downgrade_variants(parsed.header),
            AttackReason.ALG_DOWNGRADE,
        )
    elif attack == AttackName.TYP_CTY:
        _add_header_variants(
            variants,
            token,
            typ_cty_variants(parsed.header),
            AttackReason.TYP_CTY,
        )
    elif attack == AttackName.DUP_HEADER:
        _add_header_variants(
            variants,
            token,
            duplicate_header_variants(parsed.header),
            AttackReason.DUP_HEADER,
        )
    elif attack == AttackName.JWS_JWE:
        _add_header_variants(
            variants,
            token,
            jws_jwe_confusion_headers(),
            AttackReason.JWS_JWE,
        )
    elif attack == AttackName.KID:
        kid_values = kid_injection_variants(parsed.header.get("kid"))
        if extra_kid:
            kid_values.extend(extra_kid)
        for index, value in enumerate(kid_values, start=1):
            mutated = mutate_compact_token(token, header_updates={"kid": value}, keep_signature=True)
            variants.append(
                ScanVariant(
                    variant_id=f"{AttackReason.KID.value}-{index}",
                    token=mutated,
                    reason=AttackReason.KID,
                )
            )
    elif attack == AttackName.B64:
        header_variants = base64url_padding_variants(parsed.parts.header_b64)
        for index, value in enumerate(header_variants, start=1):
            mutated = f"{value}.{parsed.parts.payload_b64}.{parsed.parts.signature_b64 or ''}".rstrip(
                "."
            )
            variants.append(
                ScanVariant(
                    variant_id=(
                        f"{AttackReason.B64.value}-{B64Variant.HEADER.value}-{index}"
                    ),
                    token=mutated,
                    reason=AttackReason.B64,
                )
            )

        payload_variants = base64url_padding_variants(parsed.parts.payload_b64)
        for index, value in enumerate(payload_variants, start=1):
            mutated = f"{parsed.parts.header_b64}.{value}.{parsed.parts.signature_b64 or ''}".rstrip(
                "."
            )
            variants.append(
                ScanVariant(
                    variant_id=(
                        f"{AttackReason.B64.value}-{B64Variant.PAYLOAD.value}-{index}"
                    ),
                    token=mutated,
                    reason=AttackReason.B64,
                )
            )
    return variants


def basic_playbook(token: str) -> list[ScanVariant]:
    variants: list[ScanVariant] = []
    for attack in AttackName:
        if attack == AttackName.ALL:
            continue
        variants.extend(attack_variants(token, attack))
    return variants
