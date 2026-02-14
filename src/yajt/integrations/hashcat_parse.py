"""hashcat output parsers."""

from __future__ import annotations

from pathlib import Path


def parse_hashcat_potfile(path: str | Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or ":" not in line:
            continue
        hashed, plaintext = line.split(":", 1)
        entries.append({"hash": hashed, "plaintext": plaintext})
    return entries
