"""JSONL serializer helpers for evidence logging."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable


def _jsonable(item: Any) -> Any:
    if is_dataclass(item):
        return asdict(item)
    return item


def write_jsonl(path: str | Path, items: Iterable[Any]) -> None:
    target = Path(path)
    with target.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(_jsonable(item), ensure_ascii=True))
            handle.write("\n")


def append_jsonl(path: str | Path, items: Iterable[Any]) -> None:
    target = Path(path)
    with target.open("a", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(_jsonable(item), ensure_ascii=True))
            handle.write("\n")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    target = Path(path)
    entries: list[dict[str, Any]] = []
    with target.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries
