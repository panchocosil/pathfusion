from __future__ import annotations

from collections import Counter
from pathlib import Path

from pathfusion.models import Finding


def write_markdown(findings: list[Finding], destination: Path, target_count: int) -> None:
    findings_sorted = sorted(findings, key=lambda item: item.score, reverse=True)
    sources_counter: Counter[str] = Counter()
    for finding in findings:
        for source in finding.sources:
            sources_counter[source.value] += 1

    lines: list[str] = []
    lines.append("# PathFusion Scan Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Targets scanned: {target_count}")
    lines.append(f"- Consolidated findings: {len(findings)}")
    lines.append(f"- Katana discoveries: {sources_counter.get('katana', 0)}")
    lines.append(f"- Dirsearch discoveries: {sources_counter.get('dirsearch', 0)}")
    lines.append(f"- Feroxbuster discoveries: {sources_counter.get('feroxbuster', 0)}")
    lines.append("")

    lines.append("## Top Prioritized Findings")
    lines.append("")
    lines.append("| Score | Status | URL | Sources | Tags |")
    lines.append("|---:|---:|---|---|---|")
    for finding in findings_sorted[:50]:
        status = str(finding.status_code) if finding.status_code is not None else "-"
        sources = ", ".join(sorted(source.value for source in finding.sources))
        tags = ", ".join(sorted(finding.tags))
        lines.append(f"| {finding.score:.2f} | {status} | `{finding.url}` | {sources} | {tags} |")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Scope was restricted to provided targets by default.")
    lines.append("- Soft-404 baseline comparison was used to reduce false positives where metadata was available.")
    lines.append("- This tool supports authorized assessments only.")

    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
