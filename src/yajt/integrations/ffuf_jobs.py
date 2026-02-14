"""ffuf job exporters."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class FfufJob:
    url: str
    method: str
    wordlist: str
    headers: Mapping[str, str] | None = None
    data: str | None = None
    cookies: str | None = None
    proxy: str | None = None
    rate: int | None = None
    output: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def export_ffuf_job(job: FfufJob, path: str | Path) -> None:
    target = Path(path)
    target.write_text(json.dumps(job.to_dict(), indent=2, sort_keys=True, ensure_ascii=True))


def _header_placeholder(name: str) -> Mapping[str, str]:
    return {name: "FUZZ"}


def header_injection_job(
    url: str,
    header_name: str,
    wordlist: str,
    *,
    method: str = "GET",
    rate: int | None = None,
    proxy: str | None = None,
    output: str | None = None,
) -> FfufJob:
    return FfufJob(
        url=url,
        method=method,
        wordlist=wordlist,
        headers=_header_placeholder(header_name),
        rate=rate,
        proxy=proxy,
        output=output,
    )


def cookie_injection_job(
    url: str,
    cookie_name: str,
    wordlist: str,
    *,
    method: str = "GET",
    rate: int | None = None,
    proxy: str | None = None,
    output: str | None = None,
) -> FfufJob:
    return FfufJob(
        url=url,
        method=method,
        wordlist=wordlist,
        cookies=f"{cookie_name}=FUZZ",
        rate=rate,
        proxy=proxy,
        output=output,
    )


def query_injection_job(
    url: str,
    param_name: str,
    wordlist: str,
    *,
    method: str = "GET",
    rate: int | None = None,
    proxy: str | None = None,
    output: str | None = None,
) -> FfufJob:
    separator = "&" if "?" in url else "?"
    return FfufJob(
        url=f"{url}{separator}{param_name}=FUZZ",
        method=method,
        wordlist=wordlist,
        rate=rate,
        proxy=proxy,
        output=output,
    )


def body_injection_job(
    url: str,
    field_name: str,
    wordlist: str,
    *,
    method: str = "POST",
    rate: int | None = None,
    proxy: str | None = None,
    output: str | None = None,
) -> FfufJob:
    return FfufJob(
        url=url,
        method=method,
        wordlist=wordlist,
        data=f"{field_name}=FUZZ",
        rate=rate,
        proxy=proxy,
        output=output,
    )
