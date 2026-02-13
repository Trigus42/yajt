# YAJT (Yet Another JWT Tool)

YAJT is a modern Python 3.14 security toolkit for auditing JSON Web Tokens. It focuses on safe, reproducible analysis and defensive testing of JWT handling implementations. The design prioritizes strong typing, small composable functions, clear workflows, and integration with best-in-class external tools (ffuf, hashcat) instead of reimplementing them.

## Goals

- Decode, normalize, validate, and re-encode JWTs for canonicalization and structure checks.
- Generate and re-sign tokens across HS/RS/ES/PS families with flexible key sources.
- Provide safe, testable security checks for common JWT misconfigurations.
- Integrate with external fuzzing/cracking tools while preserving an evidence trail.

## Architecture Overview

YAJT is structured around a layered design:

1. **Domain Models**: Strongly typed dataclasses and enums describing JWTs, claims, keys, and results.
2. **Core Services**: Pure, deterministic functions for parsing, validation, canonicalization, and signing.
3. **Adapters**: Integration points for external tools (ffuf, hashcat), networking, and file I/O.
4. **Workflows**: Orchestrated sequences (playbooks, scans, resigning) built on core services.
5. **CLI**: A thin interface that maps user commands to workflows and renders structured output.

## Source Layout (planned)

- `src/yajt/models/`:
  - Typed dataclasses and enums for tokens, claims, keys, evidence, and scan results.
- `src/yajt/core/`:
  - JWT parsing/validation, canonicalization, signing, verification.
- `src/yajt/keys/`:
  - Key generation, JWKS parsing/export, caching and rotation checks.
- `src/yajt/attacks/`:
  - Variant generation, claim injection, algorithm confusion checks, header quirks.
- `src/yajt/integrations/`:
  - ffuf and hashcat job export/import parsers.
- `src/yajt/workflows/`:
  - Scans, playbooks, and orchestrated checks.
- `src/yajt/logging/`:
  - Token logbook, evidence capture, correlation.
- `src/yajt/cli/`:
  - CLI entry points and commands.

## Modules and Services

### models

- `models/token.py`: `JwtToken`, `JwtHeader`, `JwtPayload`, `JwtParts` (raw b64 segments).
- `models/claims.py`: standard claim enums, typed dicts for registered/private claims.
- `models/keys.py`: `KeyMaterial`, `KeyType`, `KeyUse`, `Jwk`, `Jwks`.
- `models/results.py`: `ValidationResult`, `VerifyResult`, `ScanFinding`.
- `models/evidence.py`: `EvidenceItem`, `RequestMeta`, `ResponseMeta`.

### core

- `core/codec.py`: base64url encode/decode, JSON parse/serialize helpers.
- `core/parse.py`: strict parsing of JWT parts, header/payload extraction.
- `core/normalize.py`: canonical JSON and base64url normalization.
- `core/validate.py`: structural validation and claim semantic checks.
- `core/sign.py`: HMAC/RSA/ECDSA/PS signing primitives.
- `core/verify.py`: signature verification and algorithm checks.

### keys

- `keys/generate.py`: RSA/EC key pair generation.
- `keys/jwk.py`: JWK import/export, JKU embedding, kid handling.
- `keys/jwks_cache.py`: JWKS caching, rotation policies, kid collision checks.

### attacks

- `attacks/variants.py`: header/payload mutation helpers.
- `attacks/claim_injection.py`: batch claim injections from lists/wordlists.
- `attacks/kid_injection.py`: traversal, null-byte, schema-based variants.
- `attacks/alg_confusion.py`: HS/RS confusion and downgrade checks.
- `attacks/quirks.py`: base64url quirks, duplicate headers, crit mishandling.
- `attacks/typ_cty.py`: typ/cty enforcement gaps.
- `attacks/jws_jwe.py`: JWS/JWE confusion probes.

### integrations

- `integrations/ffuf_jobs.py`: export fuzzing jobs (header/cookie/query/body).
- `integrations/ffuf_parse.py`: parse ffuf JSON/CSV into findings.
- `integrations/hashcat_jobs.py`: hashcat job export for HMAC cracking.
- `integrations/hashcat_parse.py`: map recovered keys to tokens.

### workflows

- `workflows/scan_playbooks.py`: curated scan sequences.
- `workflows/error_forcing.py`: malformed token generation and probes.
- `workflows/resign.py`: token build/resign flows.
- `workflows/verify.py`: end-to-end verification paths.

### logging

- `logging/logbook.py`: token registry, evidence correlation.
- `logging/serializer.py`: JSONL evidence output.

### cli

- `cli/app.py`: CLI entry, command routing.
- `cli/commands/*.py`: subcommands for decode, verify, scan, resign, fuzz, crack.

### services (cross-cutting)

- `services/policy.py`: algorithm allowlist, clock skew, claim policy.
- `services/clock.py`: time source abstraction for deterministic tests.
- `services/idgen.py`: stable token IDs and correlation IDs.
- `services/wordlists.py`: list loading and filtering for injections.

## Design Principles

- **Strong typing**: typed dicts, dataclasses, enums, and typed exceptions.
- **Small functions**: single-responsibility building blocks that are easy to test.
- **Deterministic core**: core logic is pure and side-effect free where possible.
- **Composable workflows**: scanning and testing built by composing core functions.
- **Modern dependencies**: rely on well-maintained libraries for crypto and parsing.

## External Integrations

- **ffuf**: export fuzzing jobs, parse structured results (JSON/CSV).
- **hashcat**: export cracking jobs, parse recovered keys and map to tokens.

## Safety & Ethics

YAJT is designed for offensive and defensive security testing and should be used only on systems you own or are authorized to assess.
