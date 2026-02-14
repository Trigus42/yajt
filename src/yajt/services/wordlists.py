"""Wordlist helpers."""

from __future__ import annotations

from pathlib import Path


def load_wordlist(path: str | Path) -> list[str]:
    wordlist = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    return [entry.strip() for entry in wordlist if entry.strip()]
