from __future__ import annotations

import json
import logging
from pathlib import Path

from pathfusion.models import CommandResult
from pathfusion.utils import run_command


class FeroxbusterRunner:
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
        target: str,
        depth: int,
        threads: int,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        output_file: Path,
        extensions: list[str],
        help_text: str,
    ) -> list[str]:
        cmd = [
            self.binary,
            "--url",
            target,
            "--json",
            "-o",
            str(output_file),
            "--depth",
            str(depth),
            "--threads",
            str(threads),
            "--quiet",
        ]
        if extensions:
            cmd.extend(["-x", ",".join(sorted(set(extensions)))])
        if proxy:
            cmd.extend(["--proxy", proxy])
        if insecure:
            cmd.append("-k")
        if follow_redirects:
            if self._has_flag(help_text, "--redirects"):
                cmd.append("--redirects")
            elif self._has_flag(help_text, "-r"):
                cmd.append("-r")
        elif self._has_flag(help_text, "--no-redirects"):
            cmd.append("--no-redirects")
        return cmd

    def run(
        self,
        targets: list[str],
        depth: int,
        threads: int,
        proxy: str | None,
        insecure: bool,
        follow_redirects: bool,
        extensions: list[str],
        workdir: Path,
        timeout: int = 1800,
    ) -> tuple[list[dict], list[CommandResult]]:
        all_records: list[dict] = []
        results: list[CommandResult] = []
        help_text = self._help_text()
        for index, target in enumerate(targets):
            output_file = workdir / f"ferox_{index}.jsonl"
            cmd = self._build_command(
                target,
                depth,
                threads,
                proxy,
                insecure,
                follow_redirects,
                output_file,
                extensions,
                help_text,
            )
            self.logger.debug("running feroxbuster command: %s", " ".join(cmd))
            result = run_command(cmd, timeout=timeout, cwd=workdir)
            results.append(result)
            if result.returncode != 0:
                self.logger.warning("feroxbuster failed for %s with exit code %s", target, result.returncode)
            records = self._parse_output(output_file, result.stdout)
            for record in records:
                record.setdefault("_target", target)
            all_records.extend(records)
        return all_records, results

    def _parse_output(self, output_file: Path, stdout: str) -> list[dict]:
        records: list[dict] = []
        lines = output_file.read_text(encoding="utf-8", errors="ignore").splitlines() if output_file.exists() else stdout.splitlines()
        for line in lines:
            item = line.strip()
            if not item:
                continue
            try:
                payload = json.loads(item)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                records.append(payload)
        return records
