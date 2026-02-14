"""hashcat job exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class HashcatJob:
    mode: int
    hash_file: str
    potfile: str | None = None
    rules: str | None = None
    mask: str | None = None
    wordlist: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def jwt_hmac_hash(token: str) -> str:
    return token


def export_hashcat_job(
    token: str,
    path: str | Path,
    *,
    mode: int = 16500,
    potfile: str | None = None,
    rules: str | None = None,
    mask: str | None = None,
    wordlist: str | None = None,
) -> HashcatJob:
    target = Path(path)
    target.write_text(f"{jwt_hmac_hash(token)}\n", encoding="utf-8")
    return HashcatJob(
        mode=mode,
        hash_file=str(target),
        potfile=potfile,
        rules=rules,
        mask=mask,
        wordlist=wordlist,
    )
