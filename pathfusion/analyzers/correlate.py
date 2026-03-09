from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from pathfusion.analyzers.normalize import canonical_key, normalize_host
from pathfusion.analyzers.paths import build_host_insights, detect_extension, infer_tags, parent_path
from pathfusion.models import Finding, SourceTool


@dataclass(slots=True)
class DiscoveryPlan:
    dirsearch_targets: dict[str, list[str]] = field(default_factory=dict)
    ferox_targets: dict[str, list[str]] = field(default_factory=dict)
    extensions_by_host: dict[str, list[str]] = field(default_factory=dict)


def finding_from_url(
    url: str,
    source: SourceTool,
    status_code: int | None = None,
    content_length: int | None = None,
) -> Finding:
    parsed = urlparse(url)
    path = parsed.path or "/"
    ext = detect_extension(path)
    tags = infer_tags(path, parsed.query or None)
    return Finding(
        url=url,
        normalized_url=canonical_key(url),
        host=normalize_host(parsed.hostname or ""),
        path=path,
        parent_path=parent_path(path),
        query=parsed.query or None,
        extension=ext,
        status_code=status_code,
        content_length=content_length,
        sources={source},
        tags=tags,
    )


def merge_findings(current: Finding, incoming: Finding) -> Finding:
    current.sources.update(incoming.sources)
    current.tags.update(incoming.tags)
    if current.status_code is None and incoming.status_code is not None:
        current.status_code = incoming.status_code
    if current.content_length is None and incoming.content_length is not None:
        current.content_length = incoming.content_length
    if incoming.meta:
        current.meta.update(incoming.meta)
    return current


def choose_next_targets(
    findings: list[Finding],
    seed_targets: dict[str, list[str]],
    max_dirsearch_paths_per_host: int,
    max_ferox_paths_per_host: int,
    ferox_score_threshold: float,
    default_extensions: list[str],
) -> DiscoveryPlan:
    insights = build_host_insights(findings)
    plan = DiscoveryPlan()

    for host, urls in seed_targets.items():
        roots = {
            f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
            for url in urls
            if urlparse(url).scheme and urlparse(url).netloc
        }
        candidates = set(roots)
        host_insight = insights.get(host)

        if host_insight:
            ranked_paths = sorted(
                host_insight.parent_paths,
                key=lambda p: (
                    any(keyword in p.lower() for keyword in {"admin", "api", "private", "backup", "swagger", "openapi"}),
                    p.count("/"),
                ),
                reverse=True,
            )
            for root in roots:
                for path in ranked_paths[:max_dirsearch_paths_per_host]:
                    candidates.add(urljoin(root, path.lstrip("/")))
            ext = sorted(host_insight.observed_extensions.union(default_extensions))
            plan.extensions_by_host[host] = ext
        else:
            plan.extensions_by_host[host] = sorted(set(default_extensions))

        selected_dirsearch = sorted(candidates)[:max_dirsearch_paths_per_host]
        plan.dirsearch_targets[host] = selected_dirsearch

        ferox_candidates: list[str] = []
        for finding in findings:
            if finding.host != host:
                continue
            if finding.score >= ferox_score_threshold or finding.tags.intersection(
                {"admin", "api", "swagger", "openapi", "backup", "private", "internal", "dev", "test", "upload"}
            ):
                base = f"{urlparse(finding.url).scheme}://{urlparse(finding.url).netloc}{finding.path}"
                ferox_candidates.append(base)
        plan.ferox_targets[host] = sorted(set(ferox_candidates))[:max_ferox_paths_per_host]

    return plan
