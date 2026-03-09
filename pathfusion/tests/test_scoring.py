from pathfusion.analyzers.scoring import score_finding
from pathfusion.models import BaselineComparison, Finding, SourceTool, Weights


def test_score_finding_sensitive_path_and_cross_tool() -> None:
    finding = Finding(
        url="https://example.com/admin/config.bak",
        normalized_url="https://example.com/admin/config.bak",
        host="example.com",
        path="/admin/config.bak",
        parent_path="/admin/",
        extension="bak",
        status_code=200,
        sources={SourceTool.KATANA, SourceTool.DIRSEARCH},
    )
    score, reasons = score_finding(
        finding,
        Weights(),
        BaselineComparison(is_soft_404_like=False, status_match=False, length_similarity=0.0),
    )
    assert score > 10
    assert any("keyword:admin" in reason for reason in reasons)
    assert any("cross_tool" in reason for reason in reasons)
