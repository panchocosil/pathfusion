from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path

from pathfusion.models import AppConfig, ToolPaths, Weights

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


def _merge_dict(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _from_dict(raw: dict) -> AppConfig:
    tools = ToolPaths(**raw.get("tools", {}))
    weights_raw = raw.get("weights", {})
    weights = Weights(
        keyword_weights=weights_raw.get("keyword_weights", Weights().keyword_weights),
        extension_weights=weights_raw.get("extension_weights", Weights().extension_weights),
        status_weights={int(k): float(v) for k, v in weights_raw.get("status_weights", Weights().status_weights).items()},
        cross_tool_bonus=float(weights_raw.get("cross_tool_bonus", Weights().cross_tool_bonus)),
        baseline_bonus=float(weights_raw.get("baseline_bonus", Weights().baseline_bonus)),
        depth_factor=float(weights_raw.get("depth_factor", Weights().depth_factor)),
    )
    return AppConfig(
        tools=tools,
        default_proxy=raw.get("default_proxy"),
        insecure_tls=bool(raw.get("insecure_tls", True)),
        default_wordlists=list(raw.get("default_wordlists", [])),
        host_allow_patterns=list(raw.get("host_allow_patterns", [])),
        host_deny_patterns=list(raw.get("host_deny_patterns", [])),
        default_extensions=list(raw.get("default_extensions", ["php", "txt", "html", "json"])),
        selective_recursion=bool(raw.get("selective_recursion", True)),
        max_dirsearch_paths_per_host=int(raw.get("max_dirsearch_paths_per_host", 20)),
        max_ferox_paths_per_host=int(raw.get("max_ferox_paths_per_host", 10)),
        ferox_score_threshold=float(raw.get("ferox_score_threshold", 6.0)),
        weights=weights,
    )


def load_config(path: Path | None) -> AppConfig:
    if path is None:
        return AppConfig()
    with path.open("rb") as f:
        raw = tomllib.load(f)
    return _from_dict(raw)


def merge_config(base: AppConfig, override: AppConfig | None = None) -> AppConfig:
    if override is None:
        return base
    merged = _merge_dict(asdict(base), asdict(override))
    return _from_dict(merged)


def host_allowed(host: str, allow_patterns: list[str], deny_patterns: list[str]) -> bool:
    if deny_patterns and any(re.search(pattern, host, re.IGNORECASE) for pattern in deny_patterns):
        return False
    if allow_patterns:
        return any(re.search(pattern, host, re.IGNORECASE) for pattern in allow_patterns)
    return True
