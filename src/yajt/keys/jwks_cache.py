"""JWKS parsing and cache helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import httpx

from jwcrypto.jwk import JWK, JWKSet


@dataclass(frozen=True, slots=True)
class JwksCacheEntry:
    jwks: JWKSet
    fetched_at: datetime
    ttl: timedelta

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.fetched_at + self.ttl


class JwksCache:
    def __init__(self) -> None:
        self._entries: dict[str, JwksCacheEntry] = {}

    def put(self, key: str, jwks: JWKSet, ttl: timedelta) -> None:
        self._entries[key] = JwksCacheEntry(jwks=jwks, fetched_at=datetime.now(timezone.utc), ttl=ttl)

    def get(self, key: str, now: datetime | None = None) -> JWKSet | None:
        entry = self._entries.get(key)
        if not entry:
            return None
        if entry.is_expired(now):
            self._entries.pop(key, None)
            return None
        return entry.jwks


def jwks_from_json(jwks_data: str | Mapping[str, Any]) -> JWKSet:
    if isinstance(jwks_data, str):
        return JWKSet.from_json(jwks_data)
    return JWKSet.from_json(json.dumps(jwks_data))


def jwks_kids(jwks: JWKSet) -> list[str]:
    kids: list[str] = []
    for key in jwks.get_keys():
        data = key.export(as_dict=True)
        kid = data.get("kid")
        if isinstance(kid, str):
            kids.append(kid)
    return kids


def jwks_validate(jwks: JWKSet) -> list[str]:
    warnings: list[str] = []
    keys = jwks.get_keys()
    if not keys:
        warnings.append("JWKS has no keys")
        return warnings

    kids = jwks_kids(jwks)
    if not kids:
        warnings.append("JWKS has no kid values")

    seen: set[str] = set()
    for kid in kids:
        if kid in seen:
            warnings.append(f"Duplicate kid detected: {kid}")
        seen.add(kid)

    algs: set[str] = set()
    uses: set[str] = set()
    missing_alg = False
    missing_use = False

    for key in keys:
        data = key.export(as_dict=True)
        alg = data.get("alg")
        use = data.get("use")
        if isinstance(alg, str) and alg:
            algs.add(alg)
        else:
            missing_alg = True
        if isinstance(use, str) and use:
            uses.add(use)
        else:
            missing_use = True

    if len(algs) > 1:
        warnings.append("JWKS has multiple alg values")
    if len(uses) > 1:
        warnings.append("JWKS has multiple use values")
    if missing_alg:
        warnings.append("JWKS has keys without alg")
    if missing_use:
        warnings.append("JWKS has keys without use")
    return warnings


def fetch_jwks(url: str, timeout: float = 5.0) -> tuple[JWKSet, list[str]]:
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    jwks = jwks_from_json(response.text)
    return jwks, jwks_validate(jwks)


def get_cached_jwks(
    cache: JwksCache,
    url: str,
    ttl_seconds: int = 300,
    timeout: float = 5.0,
) -> tuple[JWKSet, list[str]]:
    cached = cache.get(url)
    if cached is not None:
        return cached, []

    jwks, warnings = fetch_jwks(url, timeout=timeout)
    cache.put(url, jwks, timedelta(seconds=ttl_seconds))
    return jwks, warnings


def jwks_select_key(jwks: JWKSet, kid: str | None) -> JWK | None:
    if kid:
        try:
            return jwks.get_key(kid)
        except Exception:
            return None

    keys = jwks.get_keys()
    return keys[0] if keys else None
