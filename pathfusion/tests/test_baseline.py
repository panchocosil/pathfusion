from pathfusion.analyzers.baseline import compare_to_baseline
from pathfusion.models import BaselineProfile, BaselineSample


def test_baseline_soft_404_detection() -> None:
    profile = BaselineProfile(
        host="example.com",
        samples=[
            BaselineSample(status_code=200, content_length=1000, title=None, fingerprint=None),
            BaselineSample(status_code=200, content_length=980, title=None, fingerprint=None),
            BaselineSample(status_code=200, content_length=1020, title=None, fingerprint=None),
        ],
    )
    match = compare_to_baseline(status_code=200, content_length=995, profile=profile)
    non_match = compare_to_baseline(status_code=403, content_length=995, profile=profile)

    assert match.is_soft_404_like
    assert not non_match.is_soft_404_like
