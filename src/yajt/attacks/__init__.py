"""Attack and mutation helpers."""

from .alg_confusion import alg_downgrade_variants, alg_hs_rs_confusion_variants
from .claim_injection import batch_inject_claims, inject_claims, load_claim_injections
from .jws_jwe import jws_jwe_confusion_headers
from .kid_injection import kid_injection_variants
from .quirks import base64url_padding_variants, duplicate_header_variants
from .typ_cty import typ_cty_variants
from .variants import mutate_compact_token

__all__ = [
    "alg_downgrade_variants",
    "alg_hs_rs_confusion_variants",
    "batch_inject_claims",
    "inject_claims",
    "load_claim_injections",
    "jws_jwe_confusion_headers",
    "kid_injection_variants",
    "base64url_padding_variants",
    "duplicate_header_variants",
    "typ_cty_variants",
    "mutate_compact_token",
]
