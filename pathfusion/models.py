from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SourceTool(str, Enum):
    KATANA = "katana"
    DIRSEARCH = "dirsearch"
    FEROXBUSTER = "feroxbuster"


class OutputFormat(str, Enum):
    PRETTY = "pretty"
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    MARKDOWN = "markdown"


@dataclass(slots=True)
class ToolPaths:
    katana: str = "katana"
    dirsearch: str = "dirsearch"
    feroxbuster: str = "feroxbuster"


@dataclass(slots=True)
class Weights:
    keyword_weights: dict[str, float] = field(
        default_factory=lambda: {
            "admin": 3.0,
            "internal": 3.0,
            "backup": 4.0,
            "old": 2.0,
            "dev": 2.5,
            "test": 2.0,
            "private": 3.0,
            "config": 3.5,
            "export": 2.5,
            "swagger": 3.0,
            "openapi": 3.0,
            "upload": 2.0,
            "api": 1.5,
        }
    )
    extension_weights: dict[str, float] = field(
        default_factory=lambda: {
            "env": 5.0,
            "bak": 4.0,
            "sql": 4.0,
            "zip": 3.0,
            "json": 1.5,
            "yml": 2.0,
            "yaml": 2.0,
            "log": 2.5,
            "txt": 1.0,
            "conf": 3.0,
            "ini": 3.0,
            "pem": 4.0,
        }
    )
    status_weights: dict[int, float] = field(
        default_factory=lambda: {
            200: 2.0,
            204: 1.5,
            401: 2.5,
            403: 2.5,
            301: 1.0,
            302: 1.0,
        }
    )
    cross_tool_bonus: float = 3.0
    baseline_bonus: float = 2.0
    depth_factor: float = 0.3


@dataclass(slots=True)
class AppConfig:
    tools: ToolPaths = field(default_factory=ToolPaths)
    default_proxy: str | None = None
    insecure_tls: bool = False
    default_wordlists: list[str] = field(default_factory=list)
    host_allow_patterns: list[str] = field(default_factory=list)
    host_deny_patterns: list[str] = field(default_factory=list)
    default_extensions: list[str] = field(default_factory=lambda: ["php", "txt", "html", "json"])
    selective_recursion: bool = True
    max_dirsearch_paths_per_host: int = 20
    max_ferox_paths_per_host: int = 10
    ferox_score_threshold: float = 6.0
    weights: Weights = field(default_factory=Weights)


@dataclass(slots=True)
class ScanConfig:
    urls: list[str]
    list_file: Path | None
    proxy: str | None
    insecure: bool
    follow_redirects: bool
    katana_depth: int
    katana_concurrency: int
    wordlist: Path | None
    extensions: list[str]
    enable_ferox: bool
    ferox_depth: int
    threads: int
    output_path: Path | None
    output_format: OutputFormat
    second_pass: bool
    max_hosts: int | None
    check_only: bool
    verbose: bool
    config_path: Path | None


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(slots=True)
class BaselineSample:
    status_code: int | None
    content_length: int | None
    title: str | None
    fingerprint: str | None


@dataclass(slots=True)
class BaselineProfile:
    host: str
    samples: list[BaselineSample] = field(default_factory=list)


@dataclass(slots=True)
class BaselineComparison:
    is_soft_404_like: bool
    status_match: bool
    length_similarity: float


@dataclass(slots=True)
class Finding:
    url: str
    normalized_url: str
    host: str
    path: str
    parent_path: str
    query: str | None = None
    extension: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    sources: set[SourceTool] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def source_count(self) -> int:
        return len(self.sources)
