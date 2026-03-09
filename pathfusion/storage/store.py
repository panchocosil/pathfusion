from __future__ import annotations

from dataclasses import dataclass, field

from pathfusion.analyzers.correlate import merge_findings
from pathfusion.models import Finding


@dataclass(slots=True)
class FindingStore:
    _items: dict[str, Finding] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        existing = self._items.get(finding.normalized_url)
        if existing is None:
            self._items[finding.normalized_url] = finding
            return
        self._items[finding.normalized_url] = merge_findings(existing, finding)

    def add_many(self, findings: list[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    def all(self) -> list[Finding]:
        return list(self._items.values())

    def by_host(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self._items.values():
            grouped.setdefault(finding.host, []).append(finding)
        return grouped

    def __len__(self) -> int:
        return len(self._items)
