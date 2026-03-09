from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from pathfusion.models import Finding

SENSITIVE_KEYWORDS = {
    "admin",
    "internal",
    "backup",
    "old",
    "dev",
    "test",
    "private",
    "config",
    "export",
    "swagger",
    "openapi",
    "upload",
    "docs",
    "api",
}


@dataclass(slots=True)
class HostInsights:
    host: str
    observed_extensions: set[str] = field(default_factory=set)
    discovered_paths: set[str] = field(default_factory=set)
    parent_paths: set[str] = field(default_factory=set)
    high_signal_paths: set[str] = field(default_factory=set)


def extract_parent_paths(path: str) -> set[str]:
    normalized = path if path.startswith("/") else f"/{path}"
    segments = [segment for segment in normalized.split("/") if segment]
    if not segments:
        return {"/"}
    parents = {"/"}
    current = ""
    for segment in segments[:-1]:
        current += f"/{segment}"
        parents.add(f"{current}/")
    if normalized.endswith("/"):
        parents.add(normalized)
    return parents


def detect_extension(path: str) -> str | None:
    leaf = path.rsplit("/", maxsplit=1)[-1]
    if "." not in leaf or leaf.startswith("."):
        return None
    return leaf.rsplit(".", maxsplit=1)[-1].lower()


def infer_tags(path: str, query: str | None = None) -> set[str]:
    path_lower = path.lower()
    tags = {keyword for keyword in SENSITIVE_KEYWORDS if keyword in path_lower}
    if query:
        tags.add("query")
    if "/api/" in path_lower or path_lower.startswith("/api"):
        tags.add("api-like")
    if path_lower.endswith(".js"):
        tags.add("javascript")
    return tags


def parent_path(path: str) -> str:
    if path in {"", "/"}:
        return "/"
    if path.endswith("/"):
        trimmed = path.rstrip("/")
    else:
        trimmed = path
    if "/" not in trimmed[1:]:
        return "/"
    parent = trimmed.rsplit("/", maxsplit=1)[0]
    return f"{parent}/"


def build_host_insights(findings: list[Finding]) -> dict[str, HostInsights]:
    insights: dict[str, HostInsights] = {}
    for finding in findings:
        host = finding.host
        item = insights.setdefault(host, HostInsights(host=host))
        item.discovered_paths.add(finding.path)
        item.parent_paths.update(extract_parent_paths(finding.path))
        if finding.extension:
            item.observed_extensions.add(finding.extension)
        if finding.tags.intersection(SENSITIVE_KEYWORDS) or finding.status_code in {200, 204, 401, 403}:
            item.high_signal_paths.add(finding.path)
    return insights


def url_to_components(url: str) -> tuple[str, str, str | None]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    query = parsed.query or None
    return host, path, query
