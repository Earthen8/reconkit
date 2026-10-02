"""Shared low-level helpers used by every stage module."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import random
import re
import shutil
import string
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_id_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_filename(name: str, max_len: int = 180) -> str:
    """Collapse a string to something safe to use as a path component.

    Never used to build a shell command - only a filesystem path - but we
    still refuse separators, dotdot and leading dashes (which some tools
    would otherwise interpret as flags).
    """
    name = name.strip().lower().replace("/", "_").replace("\\", "_")
    name = _SAFE_CHARS.sub("_", name)
    name = name.lstrip("-")
    name = name.strip("._") or "unnamed"
    return name[:max_len]


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


@dataclass
class CmdResult:
    cmd: Sequence[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


def run_cmd(
    cmd: Sequence[str],
    timeout: Optional[float] = None,
    input_data: Optional[str] = None,
    cwd: Optional[str] = None,
) -> CmdResult:
    """Run an argv list (never a shell string) and always return a result.

    Never raises for timeouts or non-zero exit codes - callers decide what
    that means for tool_run status. `cmd` must be a list; this function
    deliberately never accepts shell=True so target-controlled strings
    (hostnames, titles, header values) can never be interpreted as shell
    syntax even if a caller forgot to sanitize them.
    """
    assert isinstance(cmd, (list, tuple)), "run_cmd requires an argv list, never a shell string"
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            shell=False,
        )
        return CmdResult(cmd, proc.returncode, proc.stdout, proc.stderr, False, time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        return CmdResult(cmd, None, exc.stdout or "", exc.stderr or "", True, time.monotonic() - started)
    except FileNotFoundError as exc:
        return CmdResult(cmd, None, "", str(exc), False, time.monotonic() - started)


def write_json(path: str, value: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def append_jsonl(path: str, value: Any) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(value, ensure_ascii=False, sort_keys=True))
        fh.write("\n")


def read_jsonl(path: str) -> list:
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return out


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()


def redact(value: str, keep: int = 4) -> str:
    """Keep only a small prefix/suffix of a candidate-secret string.

    Used so JS/content findings can be reported as *leads* ("a string
    matching an access-token shape was seen here") without the pipeline
    itself exfiltrating or persisting the full secret value.
    """
    if value is None:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{'*' * 6}...{value[-keep:]}"


def random_token(length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


@dataclass
class RateLimiter:
    """Simple fixed-interval pacer: `rps` requests/ops per second, ceiling 0 = unbounded."""

    rps: float = 5.0
    _last: float = field(default=0.0, init=False, repr=False)

    def wait(self) -> None:
        if self.rps <= 0:
            return
        min_interval = 1.0 / self.rps
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last = time.monotonic()


def chunked(items: Sequence, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


def ensure_dirs(*paths: str) -> None:
    for p in paths:
        Path(p).mkdir(parents=True, exist_ok=True)
