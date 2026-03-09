from __future__ import annotations

import json
import logging
import re
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

    def _tls_insecure_flag(self, help_text: str) -> str | None:
        if self._has_flag(help_text, "-tlsi", "--tlsi"):
            return "-tlsi"
        if self._has_flag(help_text, "-insecure", "--insecure"):
            return "-insecure"
        return None

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
        # Keep katana in host scope when the flag exists.
        if self._has_flag(help_text, "-fs", "--field-scope"):
            cmd.extend(["-fs", "fqdn"])
        if proxy:
            cmd.extend(["-proxy", proxy])
        if insecure:
            insecure_flag = self._tls_insecure_flag(help_text)
            if insecure_flag:
                cmd.append(insecure_flag)
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
        insecure_flag = self._tls_insecure_flag(help_text) if insecure else None
        cmd = self._build_command(targets_file, depth, concurrency, proxy, insecure, follow_redirects, help_text)
        self.logger.debug("running katana command: %s", " ".join(cmd))
        result = run_command(cmd, timeout=timeout, cwd=workdir)

        if result.returncode != 0 and "-fs" in cmd and "invalid" in result.stderr.lower():
            self.logger.debug("katana field-scope value rejected, retrying without -fs")
            no_scope_cmd = [segment for segment in cmd if segment not in {"-fs", "fqdn"}]
            self.logger.debug("running katana no-field-scope fallback: %s", " ".join(no_scope_cmd))
            result = run_command(no_scope_cmd, timeout=timeout, cwd=workdir)

        if result.returncode != 0 and "flag provided but not defined" in result.stderr:
            self.logger.debug("katana flag mismatch detected, retrying with reduced flags")
            fallback = [self.binary, "-list", str(targets_file), "-d", str(depth), "-j", "-silent"]
            if insecure_flag:
                fallback.append(insecure_flag)
            self.logger.debug("running katana fallback command: %s", " ".join(fallback))
            result = run_command(fallback, timeout=timeout, cwd=workdir)

        records = self.parse_output(result.stdout)
        if not records and result.returncode == 0:
            # Some katana versions suppress discovered URLs with -silent in JSON mode.
            fallback = [self.binary, "-list", str(targets_file), "-d", str(depth), "-j"]
            if insecure_flag:
                fallback.append(insecure_flag)
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
        url_pattern = re.compile(r"https?://[^\\s\"'<>]+", re.IGNORECASE)
        records: list[dict] = []
        seen: set[str] = set()

        def _append_url(raw_url: str, payload: dict | None = None) -> None:
            cleaned = raw_url.rstrip(".,;:)]}>").strip()
            if not cleaned.startswith(("http://", "https://")):
                return
            if cleaned in seen:
                return
            seen.add(cleaned)
            if payload:
                enriched = dict(payload)
                enriched["url"] = cleaned
                records.append(enriched)
                return
            records.append({"url": cleaned})

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
                    candidates = [
                        payload.get("url"),
                        payload.get("request", {}).get("endpoint"),
                        payload.get("request", {}).get("url"),
                        payload.get("response", {}).get("url"),
                    ]
                    for candidate in candidates:
                        if isinstance(candidate, str):
                            match = url_pattern.search(candidate)
                            if match:
                                _append_url(match.group(0), payload)
                                break
                continue
            for match in url_pattern.findall(item):
                _append_url(match)
        return records
