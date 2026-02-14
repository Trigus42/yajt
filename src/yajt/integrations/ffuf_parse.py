"""ffuf result parsers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def parse_ffuf_json(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", []) if isinstance(data, dict) else []
    parsed: list[dict[str, Any]] = []
    for result in results:
        if isinstance(result, dict):
            parsed.append(result)
    return parsed


def parse_ffuf_csv(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)
    return rows
