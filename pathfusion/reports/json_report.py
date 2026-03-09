from __future__ import annotations

import json
from pathlib import Path

from pathfusion.models import Finding


def finding_to_dict(finding: Finding) -> dict:
    return {
        "url": finding.url,
        "normalized_url": finding.normalized_url,
        "host": finding.host,
        "path": finding.path,
        "parent_path": finding.parent_path,
        "query": finding.query,
        "status_code": finding.status_code,
        "content_length": finding.content_length,
        "extension": finding.extension,
        "sources": sorted(source.value for source in finding.sources),
        "tags": sorted(finding.tags),
        "score": finding.score,
        "reasons": finding.reasons,
        "meta": finding.meta,
    }


def write_json(findings: list[Finding], destination: Path) -> None:
    payload = [finding_to_dict(finding) for finding in findings]
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_jsonl(findings: list[Finding], destination: Path) -> None:
    with destination.open("w", encoding="utf-8") as file:
        for finding in findings:
            file.write(json.dumps(finding_to_dict(finding), ensure_ascii=False) + "\n")
