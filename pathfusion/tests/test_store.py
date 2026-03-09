from pathfusion.models import Finding, SourceTool
from pathfusion.storage.store import FindingStore


def test_store_deduplicates_and_merges_sources() -> None:
    store = FindingStore()
    one = Finding(
        url="https://example.com/admin",
        normalized_url="https://example.com/admin",
        host="example.com",
        path="/admin",
        parent_path="/",
        sources={SourceTool.KATANA},
    )
    two = Finding(
        url="https://example.com/admin",
        normalized_url="https://example.com/admin",
        host="example.com",
        path="/admin",
        parent_path="/",
        sources={SourceTool.DIRSEARCH},
        status_code=403,
    )
    store.add(one)
    store.add(two)

    findings = store.all()
    assert len(findings) == 1
    assert findings[0].sources == {SourceTool.KATANA, SourceTool.DIRSEARCH}
    assert findings[0].status_code == 403
