"""Attack name and reason enums."""

from __future__ import annotations

from enum import StrEnum


class AttackName(StrEnum):
    ALG_CONFUSION = "alg-confusion"
    ALG_DOWNGRADE = "alg-downgrade"
    TYP_CTY = "typ-cty"
    DUP_HEADER = "dup-header"
    JWS_JWE = "jws-jwe"
    KID = "kid"
    B64 = "b64"
    ALL = "all"


class AttackReason(StrEnum):
    ALG_CONFUSION = "alg-confusion"
    ALG_DOWNGRADE = "alg-downgrade"
    TYP_CTY = "typ-cty"
    DUP_HEADER = "dup-header"
    JWS_JWE = "jws-jwe"
    KID = "kid"
    B64 = "b64"
    MALFORMED = "malformed"
    CLAIM_INJECTION = "claim-injection"


class B64Variant(StrEnum):
    HEADER = "header"
    PAYLOAD = "payload"


class AttackCommand(StrEnum):
    LIST = "list"


class HelpFlag(StrEnum):
    LONG = "--help"
    SHORT = "-h"


class KidArg(StrEnum):
    EXTRA = "--extra"


class DiffKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    NON_JSON = "non-json"


class DiffSection(StrEnum):
    HEADER = "header"
    PAYLOAD = "payload"


class OutputKey(StrEnum):
    VARIANTS = "variants"
    ATTACKS = "attacks"
    ID = "id"
    REASON = "reason"
    TOKEN = "token"
    HEADER = "header"
    PAYLOAD = "payload"
    PARTS = "parts"
    HEADER_B64 = "header_b64"
    PAYLOAD_B64 = "payload_b64"
    SIGNATURE_B64 = "signature_b64"
    DIFF = "diff"
    SECTION = "section"
    FIELD = "field"
    KIND = "kind"
    BEFORE = "before"
    AFTER = "after"
    CLAIM = "claim"
    VALUE = "value"
    EVENT = "event"
    VARIANT_COUNT = "variant_count"
    HELP = "help"


class AttackError(StrEnum):
    UNKNOWN_ATTACK = "Unknown attack"
    PROVIDE_TOKEN = "Provide --token"
    PROVIDE_METHOD = "Provide at least one attack method"
    LIST_COMBINATION = "list cannot be combined with attack methods"
    ALL_ALONE = "all must be used alone"
    KID_EXTRA_ONLY = "kid supports --extra only"
    KID_EXTRA_VALUE = "--extra requires a value"
    INJECT_CLAIM_FORMAT = "inject-claim must be claim=value-or-path"


class AttackOptionHelp(StrEnum):
    TOKEN = "JWT in compact form"
    MALFORMED = "Include malformed variants"
    INJECT_CLAIM = "Claim injection in form claim=value-or-path (repeatable)"
    LOGBOOK = "JSONL logbook path"
    PRETTY = "Pretty JSON output"


class AttackHelp(StrEnum):
    ALG_CONFUSION = "alg-confusion: HS/RS confusion variants"
    ALG_DOWNGRADE = "alg-downgrade: downgrade alg to weaker/default"
    TYP_CTY = "typ-cty: typ/cty enforcement gap probes"
    DUP_HEADER = "dup-header: duplicate header key variants"
    JWS_JWE = "jws-jwe: JWS/JWE confusion headers"
    KID = "kid: kid injection variants; use --extra value"
    B64 = "b64: base64url padding/charset variants"
    ALL = "all: run all attack variants"
