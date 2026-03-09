from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, urlunparse

from pathfusion.config import host_allowed


def normalize_url(url: str) -> str:
    raw = url.strip()
    if not raw:
        raise ValueError("Empty URL")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme for target: {url}")
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    normalized = parsed._replace(path=path, fragment="")
    return urlunparse(normalized)


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path = f"/{path}"
    while "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        return path
    return path


def normalize_targets(
    urls: list[str],
    list_file: Path | None,
    max_hosts: int | None,
    allow_patterns: list[str],
    deny_patterns: list[str],
) -> list[str]:
    combined = [u for u in urls if u]
    if list_file:
        with list_file.open("r", encoding="utf-8") as f:
            combined.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))

    normalized: list[str] = []
    seen: set[str] = set()
    hosts: set[str] = set()
    for raw in combined:
        try:
            url = normalize_url(raw)
        except ValueError:
            continue
        host = urlparse(url).hostname or ""
        if not host_allowed(host, allow_patterns, deny_patterns):
            continue
        if max_hosts is not None and host not in hosts and len(hosts) >= max_hosts:
            continue
        if url in seen:
            continue
        seen.add(url)
        hosts.add(host)
        normalized.append(url)
    return normalized


def group_by_host(urls: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for url in urls:
        host = urlparse(url).hostname or ""
        grouped.setdefault(host, []).append(url)
    return grouped


def canonical_key(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))
