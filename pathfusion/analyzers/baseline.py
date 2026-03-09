from __future__ import annotations

import logging
import re
from statistics import median
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from pathfusion.models import BaselineComparison, BaselineProfile, BaselineSample
from pathfusion.utils import quick_fingerprint, random_path_token

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    return " ".join(match.group(1).split())[:200]


def build_baseline_profile(
    base_url: str,
    insecure: bool = False,
    follow_redirects: bool = False,
    proxy: str | None = None,
    samples: int = 3,
    timeout: int = 10,
    logger: logging.Logger | None = None,
) -> BaselineProfile:
    if insecure:
        urllib3.disable_warnings(InsecureRequestWarning)

    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    profile = BaselineProfile(host=parsed.hostname or "")
    for _ in range(samples):
        nonce = random_path_token()
        url = urljoin(root, f"__pathfusion_nonexistent_{nonce}")
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=not insecure,
                proxies=proxies,
                allow_redirects=follow_redirects,
                headers={"User-Agent": "pathfusion/0.1"},
            )
            text = response.text or ""
            sample = BaselineSample(
                status_code=response.status_code,
                content_length=len(text.encode("utf-8", errors="ignore")),
                title=_extract_title(text),
                fingerprint=quick_fingerprint(text),
            )
            profile.samples.append(sample)
        except requests.RequestException as exc:
            if logger:
                logger.debug("baseline probe failed for %s: %s", root, exc)
    return profile


def compare_to_baseline(
    status_code: int | None,
    content_length: int | None,
    profile: BaselineProfile | None,
) -> BaselineComparison:
    if profile is None or not profile.samples:
        return BaselineComparison(is_soft_404_like=False, status_match=False, length_similarity=0.0)

    statuses = [s.status_code for s in profile.samples if s.status_code is not None]
    lengths = [s.content_length for s in profile.samples if s.content_length is not None]

    baseline_status = max(set(statuses), key=statuses.count) if statuses else None
    baseline_length = median(lengths) if lengths else None

    status_match = baseline_status is not None and status_code == baseline_status

    similarity = 0.0
    if baseline_length and content_length is not None and baseline_length > 0:
        similarity = 1 - min(abs(content_length - baseline_length) / baseline_length, 1)

    # If content length is missing from brute-force tool output but the status
    # matches the baseline status, treat it as likely soft-404/wildcard.
    if status_match and content_length is None:
        similarity = 1.0

    is_soft_404_like = bool(status_match and similarity >= 0.90)
    return BaselineComparison(
        is_soft_404_like=is_soft_404_like,
        status_match=status_match,
        length_similarity=round(similarity, 3),
    )
