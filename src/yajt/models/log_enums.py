"""Log event enums."""

from __future__ import annotations

from enum import StrEnum


class LogEvent(StrEnum):
    VERIFY = "verify"
    RESIGN = "resign"
    ATTACK = "attack"
