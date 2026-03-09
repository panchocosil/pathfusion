from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from pathfusion.models import CommandResult
from pathfusion.utils import run_command


class DirsearchRunner:
    def __init__(self, binary: str, logger: logging.Logger) -> None:
        self.binary = binary
        self.logger = logger
        self._help_cache: str | None = None

    def _help_text(self) -> str:
        if self._help_cache is not None:
            return self._help_cache
        probe = run_command([self.binary, "-h"], timeout=30)
        self._help_cache = f"{probe.stdout}\n{probe.stderr}".lower()
        return self._help_cache

    @staticmethod
    def _has_flag(help_text: str, *flags: str) -> bool:
        return any(flag.lower() in help_text for flag in flags)

    @staticmethod
    def _size_to_bytes(raw: str) -> int | None:
        match = re.search(r"(\d+(?:\.\d+)?)\s*([KMG]?B)\b", raw, re.IGNORECASE)
        if not match:
            return None
        value = float(match.group(1))
        unit = match.group(2).upper()
        multiplier = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}.get(unit, 1)
        return int(value * multiplier)

    @staticmethod
    def _stderr_summary(stderr: str) -> str:
        if not stderr.strip():
            return ""
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        if not lines:
            return ""
        if any("traceback (most recent call last)" in line.lower() for line in lines):
            return lines[-1]
        return lines[0][:300]

    def _build_command(
        self,
        target: str,
        threads: int,
        wordlist: Path | None,
        extensions: list[str],
        request_timeout: int,
        headers: list[str],
        full_url: bool,
        random_agent: bool,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        output_file: Path,
        recurse: bool,
        help_text: str,
    ) -> list[str]:
        cmd = [self.binary, "-u", target]

        if self._has_flag(help_text, "--threads"):
            cmd.extend(["--threads", str(threads)])
        elif self._has_flag(help_text, "-t"):
            cmd.extend(["-t", str(threads)])

        if self._has_flag(help_text, "--json-report"):
            cmd.extend(["--json-report", str(output_file)])
        elif self._has_flag(help_text, "--format") and self._has_flag(help_text, "--output"):
            cmd.extend(["--format", "json", "--output", str(output_file)])
        elif self._has_flag(help_text, "--plain-text-report"):
            cmd.extend(["--plain-text-report", str(output_file)])

        if self._has_flag(help_text, "--quiet-mode"):
            cmd.append("--quiet-mode")
        elif self._has_flag(help_text, "-q", "--quiet"):
            cmd.append("-q")

        if wordlist:
            cmd.extend(["-w", str(wordlist)])
        if extensions:
            cmd.extend(["-e", ",".join(sorted(set(extensions)))])
        if self._has_flag(help_text, "--timeout"):
            cmd.extend(["--timeout", str(request_timeout)])
        if full_url and self._has_flag(help_text, "--full-url"):
            cmd.append("--full-url")
        if random_agent and self._has_flag(help_text, "--random-agent"):
            cmd.append("--random-agent")
        if headers and self._has_flag(help_text, "-H", "--header"):
            for header in headers:
                cmd.extend(["-H", header])
        if proxy and self._has_flag(help_text, "--proxy"):
            cmd.extend(["--proxy", proxy])
        if insecure and self._has_flag(help_text, "--insecure"):
            cmd.append("--insecure")
        if follow_redirects and self._has_flag(help_text, "--follow-redirects"):
            cmd.append("--follow-redirects")
        if not follow_redirects and self._has_flag(help_text, "--no-follow-redirects"):
            cmd.append("--no-follow-redirects")
        if recurse and self._has_flag(help_text, "--recursive"):
            cmd.append("--recursive")
        return cmd

    def run(
        self,
        targets: list[str],
        threads: int,
        wordlist: Path | None,
        extensions: list[str],
        request_timeout: int,
        headers: list[str],
        full_url: bool,
        random_agent: bool,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        recurse: bool,
        workdir: Path,
        timeout: int = 1800,
    ) -> tuple[list[dict], list[CommandResult]]:
        all_records: list[dict] = []
        results: list[CommandResult] = []
        help_text = self._help_text()
        for index, target in enumerate(targets):
            output_file = workdir / f"dirsearch_{index}.json"
            cmd = self._build_command(
                target,
                threads,
                wordlist,
                extensions,
                request_timeout,
                headers,
                full_url,
                random_agent,
                proxy,
                insecure,
                follow_redirects,
                output_file,
                recurse,
                help_text,
            )
            self.logger.debug("running dirsearch command: %s", " ".join(cmd))
            result = run_command(cmd, timeout=timeout, cwd=workdir)
            results.append(result)

            if result.returncode != 0:
                self.logger.warning("dirsearch failed for %s with exit code %s", target, result.returncode)
                if result.stderr.strip():
                    self.logger.warning("dirsearch stderr: %s", self._stderr_summary(result.stderr))
                    self.logger.debug("dirsearch stderr (truncated): %s", result.stderr[:2000])
                parse_error = any(
                    token in result.stderr.lower()
                    for token in {"unrecognized arguments", "unknown argument", "invalid choice", "usage:"}
                )
                if parse_error or "flag provided but not defined" in result.stderr.lower():
                    fallback_cmd = [self.binary, "-u", target]
                    if self._has_flag(help_text, "-q", "--quiet"):
                        fallback_cmd.append("-q")
                    if wordlist:
                        fallback_cmd.extend(["-w", str(wordlist)])
                    if extensions:
                        fallback_cmd.extend(["-e", ",".join(sorted(set(extensions)))])
                    if self._has_flag(help_text, "--timeout"):
                        fallback_cmd.extend(["--timeout", str(request_timeout)])
                    if full_url and self._has_flag(help_text, "--full-url"):
                        fallback_cmd.append("--full-url")
                    if random_agent and self._has_flag(help_text, "--random-agent"):
                        fallback_cmd.append("--random-agent")
                    if headers and self._has_flag(help_text, "-H", "--header"):
                        for header in headers:
                            fallback_cmd.extend(["-H", header])
                    if follow_redirects and self._has_flag(help_text, "--follow-redirects"):
                        fallback_cmd.append("--follow-redirects")
                    if not follow_redirects and self._has_flag(help_text, "--no-follow-redirects"):
                        fallback_cmd.append("--no-follow-redirects")
                    if self._has_flag(help_text, "--format") and self._has_flag(help_text, "--output"):
                        fallback_cmd.extend(["--format", "json", "--output", str(output_file)])
                    self.logger.warning("retrying dirsearch with compatibility fallback for %s", target)
                    self.logger.debug("running dirsearch compatibility fallback: %s", " ".join(fallback_cmd))
                    result = run_command(fallback_cmd, timeout=timeout, cwd=workdir)
                    results.append(result)
                elif recurse:
                    fallback_cmd = self._build_command(
                        target,
                        threads,
                        wordlist,
                        extensions,
                        request_timeout,
                        headers,
                        full_url,
                        random_agent,
                        proxy,
                        insecure,
                        follow_redirects,
                        output_file,
                        recurse=False,
                        help_text=help_text,
                    )
                    self.logger.debug("running dirsearch recurse-off fallback: %s", " ".join(fallback_cmd))
                    result = run_command(fallback_cmd, timeout=timeout, cwd=workdir)
                    results.append(result)

            records = self._parse_report(output_file)
            if not records:
                records = self._parse_stdout(result.stdout, target)
            for record in records:
                record.setdefault("_target", target)
            all_records.extend(records)
        return all_records, results

    def _parse_stdout(self, stdout: str, target: str) -> list[dict]:
        records: list[dict] = []
        for line in stdout.splitlines():
            item = line.strip()
            if not item:
                continue
            if item.startswith("{"):
                try:
                    payload = json.loads(item)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    records.append(payload)
                    continue
            # example: [12:00:01] 200 -  123B  - /admin/
            status_match = re.search(r"\b(20[0-9]|30[0-9]|40[0-9]|50[0-9])\b", item)
            status = int(status_match.group(1)) if status_match else None
            length = self._size_to_bytes(item)
            path_match = re.search(r"(https?://\S+|/\S+)$", item)
            if not path_match:
                continue
            value = path_match.group(1)
            if value.startswith("http://") or value.startswith("https://"):
                records.append({"status": status, "url": value, "content_length": length})
            else:
                records.append({"status": status, "path": value, "content_length": length, "_target": target})
        return records

    def _parse_report(self, report_path: Path) -> list[dict]:
        if not report_path.exists():
            return []
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        records: list[dict] = []
        if isinstance(payload, list):
            records.extend(item for item in payload if isinstance(item, dict))
        elif isinstance(payload, dict):
            if "results" in payload and isinstance(payload["results"], dict):
                for _, items in payload["results"].items():
                    if isinstance(items, list):
                        records.extend(item for item in items if isinstance(item, dict))
            elif "results" in payload and isinstance(payload["results"], list):
                records.extend(item for item in payload["results"] if isinstance(item, dict))
            elif "data" in payload and isinstance(payload["data"], list):
                records.extend(item for item in payload["data"] if isinstance(item, dict))
        return records
