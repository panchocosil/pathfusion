from pathfusion.analyzers.paths import extract_parent_paths, parent_path


def test_extract_parent_paths() -> None:
    parents = extract_parent_paths("/api/v1/users")
    assert "/" in parents
    assert "/api/" in parents
    assert "/api/v1/" in parents


def test_parent_path() -> None:
    assert parent_path("/admin/login") == "/admin/"
    assert parent_path("/") == "/"
