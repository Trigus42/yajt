# YAJT (Yet Another JWT Tool)

YAJT is a modern Python 3.14 security toolkit for auditing JSON Web Tokens. It prioritizes strong typing, small composable functions, deterministic core logic, and a JSON-first CLI. It integrates with external tools (ffuf, hashcat) rather than reimplementing them.

## Goals

- Decode, normalize, validate, and re-encode JWTs for canonicalization and structure checks.
- Generate and re-sign tokens across HS/RS/ES/PS families with flexible key sources.
- Provide safe, testable security checks for common JWT misconfigurations.
- Integrate with external fuzzing/cracking tools while preserving an evidence trail.

## Architecture Overview

YAJT uses a layered architecture:

1. **Domain Models**: Dataclasses and enums for tokens, claims, keys, results, evidence, and CLI enums.
2. **Core Services**: Pure parsing, validation, canonicalization, signing, and verification.
3. **Adapters**: External tool integration (ffuf/hashcat), network fetch (JWKS), file I/O.
4. **Workflows**: Orchestrated sequences for verify, resign, and attack variants.
5. **CLI**: Typer-based command surface with JSON output.

## Current Source Layout

- `src/yajt/models/`
- `src/yajt/core/`
- `src/yajt/keys/`
- `src/yajt/attacks/`
- `src/yajt/integrations/`
- `src/yajt/workflows/`
- `src/yajt/logging/`
- `src/yajt/cli/`
- `tests/`

## Modules and Services

### models

- `models/jwt_models.py`: `JwtToken`, `JwtHeader`, `JwtPayload`, `JwtParts`.
- `models/claims.py`: registered claim enums and typed claim dicts.
- `models/keys.py`: `KeyMaterial`, `KeyType`, `KeyUse`, `Jwk`, `Jwks`.
- `models/results.py`: `ValidationResult`, `VerifyResult`, `ScanFinding`.
- `models/evidence.py`: `EvidenceItem`, `RequestMeta`, `ResponseMeta`.
- `models/attack_enums.py`: CLI attack enums and output keys.
- `models/log_enums.py`: log event enums.

### core

- `core/codec.py`: base64url encode/decode, JSON parse/serialize helpers.
- `core/parse.py`: strict parsing of JWT parts, header/payload extraction.
- `core/normalize.py`: canonical JSON and base64url normalization.
- `core/validate.py`: structure validation plus typ/cty/crit warnings and claim checks.
- `core/sign.py`: signing via jwcrypto.
- `core/verify.py`: signature verification and algorithm checks.

### keys

- `keys/generate.py`: RSA/EC key pair generation.
- `keys/jwk.py`: JWK import/export, kid handling, public export.
- `keys/jwks_cache.py`: JWKS caching, fetch helpers, and validation warnings.

### attacks

- `attacks/variants.py`: header/payload mutation helpers.
- `attacks/claim_injection.py`: batch claim injections from wordlists.
- `attacks/kid_injection.py`: traversal, null-byte, schema-based variants.
- `attacks/alg_confusion.py`: HS/RS confusion and downgrade checks.
- `attacks/quirks.py`: base64url quirks, duplicate headers.
- `attacks/typ_cty.py`: typ/cty enforcement gaps.
- `attacks/jws_jwe.py`: JWS/JWE confusion probes.

### integrations

- `integrations/ffuf_jobs.py`: export fuzzing jobs (header/cookie/query/body).
- `integrations/ffuf_parse.py`: parse ffuf JSON/CSV into results.
- `integrations/hashcat_jobs.py`: hashcat job export for HMAC cracking.
- `integrations/hashcat_parse.py`: map recovered keys to tokens.

### workflows

- `workflows/scan_playbooks.py`: attack variant generation per attack name.
- `workflows/error_forcing.py`: malformed token generation.
- `workflows/claim_injection.py`: claim injection variants (wordlist and value based).
- `workflows/resign.py`: resign flows.
- `workflows/verify.py`: verification with claims validation.

### logging

- `logging/logbook.py`: token registry and evidence correlation.
- `logging/serializer.py`: JSONL read/write/append.
- `cli/commands/logging_utils.py`: CLI logbook helpers with token snapshots.

### cli

- `cli/app.py`: CLI entry, command routing.
- `cli/commands/attack.py`: attack sequencing, per-variant diffs, list, method help.
- `cli/commands/decode.py`: decode and inspect.
- `cli/commands/validate.py`: structure and claim validation.
- `cli/commands/verify.py`: signature verification and JWKS fetch.
- `cli/commands/resign.py`: resign with supplied key.
- `cli/commands/edit.py`: interactive header/payload editor.
- `cli/commands/keys.py`: key generation and JWK helpers.
- `cli/commands/fuzz.py`: ffuf job export and parse.
- `cli/commands/crack.py`: hashcat job export and parse.

### services (cross-cutting)

- `services/policy.py`: claim policy and clock skew.
- `services/clock.py`: time source abstraction.
- `services/idgen.py`: stable token IDs and correlation IDs.
- `services/wordlists.py`: wordlist loading and filtering.

## CLI Surface

- `yajt decode <token> [--pretty|--compact]`
- `yajt validate <token> [--claims] [--issuer <iss>] [--audience <aud> ...] [--skew <sec>] [--pretty|--compact]`
- `yajt verify <token> (--jwk <json> | --jwk-file <file> | --pem <file> | --jwks <json> | --jwks-file <file> | --jwks-url <url>) [--kid <kid>] [--claims] [--issuer <iss>] [--audience <aud> ...] [--skew <sec>] [--jwks-ttl <sec>] [--jwks-timeout <sec>] [--logbook <jsonl>] [--pretty|--compact]`
- `yajt resign <token> --alg <alg> (--jwk <json> | --jwk-file <file> | --pem <file>) [--logbook <jsonl>]`
- `yajt attack list`
- `yajt attack -t <token> [--malformed] [--inject-claim <claim=wordlist-or-value> ...] [--logbook <jsonl>] [--pretty|--compact] <method> <method-args> [<method> <method-args> ...]`
- `yajt keys generate-rsa [--bits <n>] [--kid <kid>] [--use sig|enc] [--alg <alg>] [--public] [--pretty|--compact]`
- `yajt keys generate-ec [--curve <name>] [--kid <kid>] [--use sig|enc] [--alg <alg>] [--public] [--pretty|--compact]`
- `yajt keys from-pem <path> [--password <pw>] [--kid <kid>] [--use sig|enc] [--alg <alg>] [--public] [--pretty|--compact]`
- `yajt keys public (--jwk <json> | --file <path>) [--pretty|--compact]`
- `yajt keys jwks-select (--jwks <json> | --file <path>) [--kid <kid>] [--pretty|--compact]`
- `yajt fuzz export <url> --wordlist <file> --mode header|cookie|query|body --name <name> [--method <verb>] [--proxy <url>] [--rate <n>] --output <file>`
- `yajt fuzz parse <file> [--format json|csv] [--pretty|--compact]`
- `yajt crack export <token> --output <file> [--mode 16500] [--wordlist <file>] [--rules <file>] [--mask <pattern>] [--potfile <file>] [--pretty|--compact]`
- `yajt crack parse <potfile> [--pretty|--compact]`
- `yajt edit <token> [--header <json>] [--payload <json|string|b64:...>] [--keep-signature]`

## Design Principles

- **Strong typing**: typed dicts, dataclasses, enums, and typed exceptions.
- **Small functions**: single-responsibility building blocks that are easy to test.
- **Deterministic core**: core logic is pure and side-effect free where possible.
- **Composable workflows**: scanning and testing built by composing core functions.
- **Modern dependencies**: rely on well-maintained libraries for crypto and parsing.
- **CLI**: Typer-based commands with JSON-first output.
- **Tooling**: ruff for linting, pyright for type checks, pytest for tests.
- **Enums first**: command names, output keys, and attack identifiers are backed by enums.

## External Integrations

- **ffuf**: export fuzzing jobs, parse structured results (JSON/CSV).
- **hashcat**: export cracking jobs, parse recovered keys and map to tokens.

## Safety & Ethics

YAJT is designed for offensive and defensive security testing and should be used only on systems you own or are authorized to assess.
