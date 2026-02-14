"""Token logbook and evidence correlation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..models.evidence import EvidenceItem
from ..models.jwt_models import JwtToken
from ..services.idgen import token_id


@dataclass
class LogBook:
    tokens: dict[str, JwtToken] = field(default_factory=dict)
    evidence: list[EvidenceItem] = field(default_factory=list)

    def register_token(self, token: JwtToken) -> str:
        token_key = token_id(token.parts)
        self.tokens[token_key] = token
        return token_key

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence.append(item)

    def extend_evidence(self, items: Iterable[EvidenceItem]) -> None:
        self.evidence.extend(items)
