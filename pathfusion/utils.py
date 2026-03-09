from __future__ import annotations

import hashlib
import logging
import os
import random
import shutil
import string
import subprocess
import tempfile
from pathlib import Path

from rich.logging import RichHandler

from pathfusion.models import CommandResult

LOGGER_NAME = "pathfusion"


def configure_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.handlers.clear()
    handler = RichHandler(show_path=False, rich_tracebacks=True)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def run_command(
    command: list[str],
    timeout: int = 600,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    base_env = os.environ.copy()
    if env:
        base_env.update(env)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=base_env,
            check=False,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except FileNotFoundError:
        return CommandResult(command=command, returncode=127, stdout="", stderr=f"binary not found: {command[0]}")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=f"command timed out after {timeout}s",
        )


def ensure_binary(binary: str) -> bool:
    return shutil.which(binary) is not None


def preflight_check(required_tools: dict[str, str]) -> tuple[bool, dict[str, str]]:
    statuses: dict[str, str] = {}
    ok = True
    for name, binary in required_tools.items():
        if ensure_binary(binary):
            statuses[name] = f"OK ({binary})"
        else:
            ok = False
            statuses[name] = f"MISSING ({binary})"
    return ok, statuses


def create_workdir(prefix: str = "pathfusion-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def random_path_token(length: int = 14) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def quick_fingerprint(text: str, max_chars: int = 4096) -> str:
    return hashlib.sha1(text[:max_chars].encode("utf-8", errors="ignore")).hexdigest()
