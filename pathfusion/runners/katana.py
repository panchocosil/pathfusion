from __future__ import annotations

import json
import logging
from pathlib import Path

from pathfusion.models import CommandResult
from pathfusion.utils import run_command


class KatanaRunner:
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

    def _build_command(
        self,
        targets_file: Path,
        depth: int,
        concurrency: int,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        help_text: str,
    ) -> list[str]:
        cmd = [
            self.binary,
            "-list",
            str(targets_file),
            "-d",
            str(depth),
            "-c",
            str(concurrency),
            "-j",
            "-silent",
        ]
        if proxy:
            cmd.extend(["-proxy", proxy])
        if insecure:
            cmd.append("-insecure")
        if follow_redirects:
            if self._has_flag(help_text, "--follow-redirects"):
                cmd.append("--follow-redirects")
            elif self._has_flag(help_text, "-fr"):
                cmd.append("-fr")
        else:
            if self._has_flag(help_text, "--no-follow-redirects"):
                cmd.append("--no-follow-redirects")
            elif self._has_flag(help_text, "--disable-redirects", "-dr"):
                cmd.append("-dr")
        return cmd

    def run(
        self,
        targets: list[str],
        depth: int,
        concurrency: int,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        workdir: Path,
        timeout: int = 1800,
    ) -> tuple[list[dict], CommandResult]:
        targets_file = workdir / "katana_targets.txt"
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

        help_text = self._help_text()
        cmd = self._build_command(targets_file, depth, concurrency, proxy, insecure, follow_redirects, help_text)
        self.logger.debug("running katana command: %s", " ".join(cmd))
        result = run_command(cmd, timeout=timeout, cwd=workdir)

        if result.returncode != 0 and "flag provided but not defined" in result.stderr:
            self.logger.debug("katana flag mismatch detected, retrying with reduced flags")
            fallback = [self.binary, "-list", str(targets_file), "-d", str(depth), "-j", "-silent"]
            self.logger.debug("running katana fallback command: %s", " ".join(fallback))
            result = run_command(fallback, timeout=timeout, cwd=workdir)

        records = self.parse_output(result.stdout)
        if not records and result.returncode == 0:
            # Some katana versions suppress discovered URLs with -silent in JSON mode.
            fallback = [self.binary, "-list", str(targets_file), "-d", str(depth), "-j"]
            self.logger.debug("running katana no-silent fallback: %s", " ".join(fallback))
            result_retry = run_command(fallback, timeout=timeout, cwd=workdir)
            retry_records = self.parse_output(result_retry.stdout)
            if retry_records:
                result = result_retry
                records = retry_records

        if not records:
            # Older versions or non-json output may leak URLs to stderr.
            records = self.parse_output(result.stderr)

        if result.returncode != 0:
            self.logger.warning("katana exited with non-zero status (%s)", result.returncode)
            if result.stderr.strip():
                self.logger.warning("katana stderr: %s", result.stderr.strip()[:500])
        return records, result

    def parse_output(self, stdout: str) -> list[dict]:
        records: list[dict] = []
        for line in stdout.splitlines():
            item = line.strip()
            if not item:
                continue
            if item.startswith("{"):
                try:
                    payload = json.loads(item)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    url = payload.get("url") or payload.get("request", {}).get("endpoint")
                    if url:
                        records.append(payload)
                continue
            records.append({"url": item})
        return records
