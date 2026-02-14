YAJT is a modern Python 3.14 security toolkit for auditing JSON Web Tokens. It focuses on safe, reproducible analysis and defensive testing of JWT handling implementations.

## Install

- Use Astral uv: `uv sync`

## Quick Usage

- Decode: `yajt decode <token>`
- Validate structure/claims: `yajt validate <token> --claims`
- Verify signature: `yajt verify <token> --jwk-file key.json`
- Resign: `yajt resign <token> --alg HS256 --jwk-file key.json`
- Attack variants: `yajt attack -t <token> alg-downgrade dup-header`
- Attack list: `yajt attack list`
- Inject claims: `yajt attack -t <token> alg-confusion --inject-claim role=wordlist.txt`
- Edit header/payload: `yajt edit <token>`

## Tooling

- Lint: `ruff check .`
- Type check: `pyright`
- Tests: `pytest`
