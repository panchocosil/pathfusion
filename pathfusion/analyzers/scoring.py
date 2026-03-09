from __future__ import annotations

from pathfusion.models import BaselineComparison, Finding, Weights


def depth_of(path: str) -> int:
    return len([segment for segment in path.split("/") if segment])


def score_finding(
    finding: Finding,
    weights: Weights,
    baseline: BaselineComparison | None = None,
) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    for keyword, weight in weights.keyword_weights.items():
        if keyword in finding.path.lower():
            score += weight
            reasons.append(f"keyword:{keyword}+{weight}")

    if finding.extension and finding.extension in weights.extension_weights:
        ext_weight = weights.extension_weights[finding.extension]
        score += ext_weight
        reasons.append(f"ext:{finding.extension}+{ext_weight}")

    if finding.status_code is not None and finding.status_code in weights.status_weights:
        status_weight = weights.status_weights[finding.status_code]
        score += status_weight
        reasons.append(f"status:{finding.status_code}+{status_weight}")

    if finding.source_count() > 1:
        bonus = weights.cross_tool_bonus * (finding.source_count() - 1)
        score += bonus
        reasons.append(f"cross_tool+{bonus}")

    depth_bonus = depth_of(finding.path) * weights.depth_factor
    score += depth_bonus
    reasons.append(f"depth+{depth_bonus:.2f}")

    if baseline and not baseline.is_soft_404_like:
        score += weights.baseline_bonus
        reasons.append(f"baseline_diff+{weights.baseline_bonus}")

    return round(score, 2), reasons


def apply_scores(
    findings: list[Finding],
    weights: Weights,
    baseline_map: dict[str, BaselineComparison] | None = None,
) -> None:
    for finding in findings:
        baseline = baseline_map.get(finding.normalized_url) if baseline_map else None
        finding.score, finding.reasons = score_finding(finding, weights, baseline)
