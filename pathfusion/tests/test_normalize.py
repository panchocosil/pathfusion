from pathlib import Path

from pathfusion.analyzers.normalize import canonical_key, normalize_host, normalize_targets, normalize_url


def test_normalize_url_adds_scheme() -> None:
    assert normalize_url("example.com/path") == "https://example.com/path"


def test_canonical_key_strips_fragment_and_trailing_slash() -> None:
    assert canonical_key("https://example.com/admin/#x") == "https://example.com/admin"


def test_normalize_targets_deduplicates(tmp_path: Path) -> None:
    file = tmp_path / "targets.txt"
    file.write_text("https://a.com\nhttps://a.com\n", encoding="utf-8")
    targets = normalize_targets(
        urls=["https://a.com", "https://a.com"],
        list_file=file,
        max_hosts=None,
        allow_patterns=[],
        deny_patterns=[],
    )
    assert targets == ["https://a.com/"]


def test_normalize_host_strips_dot_and_case() -> None:
    assert normalize_host("WWW.Example.COM.") == "www.example.com"
