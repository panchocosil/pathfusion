from __future__ import annotations

import csv
from pathlib import Path

from pathfusion.models import Finding


def write_csv(findings: list[Finding], destination: Path) -> None:
    fieldnames = [
        "url",
        "normalized_url",
        "host",
        "path",
        "parent_path",
        "query",
        "status_code",
        "content_length",
        "extension",
        "sources",
        "tags",
        "score",
        "reasons",
    ]
    with destination.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "url": finding.url,
                    "normalized_url": finding.normalized_url,
                    "host": finding.host,
                    "path": finding.path,
                    "parent_path": finding.parent_path,
                    "query": finding.query or "",
                    "status_code": finding.status_code or "",
                    "content_length": finding.content_length or "",
                    "extension": finding.extension or "",
                    "sources": ",".join(sorted(source.value for source in finding.sources)),
                    "tags": ",".join(sorted(finding.tags)),
                    "score": finding.score,
                    "reasons": " | ".join(finding.reasons),
                }
            )
