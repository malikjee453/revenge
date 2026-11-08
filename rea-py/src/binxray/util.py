"""Shared helpers: path handling, safe reading, and the Evidence result envelope."""
from __future__ import annotations

import mmap
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


class ReaError(Exception):
    """A user-facing error (bad path, malformed input, unsupported format)."""


def resolve_file(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise ReaError(f"Path does not exist: {path}")
    if not p.is_file():
        raise ReaError(f"Not a regular file: {path}")
    return p


def resolve_any(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise ReaError(f"Path does not exist: {path}")
    return p


@contextmanager
def open_mmap(path: str) -> Iterator[mmap.mmap]:
    """Read-only memory map of a file. Targets are never modified or executed."""
    p = resolve_file(path)
    if p.stat().st_size == 0:
        raise ReaError("File is empty")
    with open(p, "rb") as fh:
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            yield m
        finally:
            m.close()


def cstring(data: Any, offset: int, limit: int = 4096) -> str:
    end = offset
    n = len(data)
    while end < n and end - offset < limit and data[end] != 0:
        end += 1
    return bytes(data[offset:end]).decode("utf-8", errors="replace")


def result(
    tool: str,
    target: str,
    findings: Dict[str, Any],
    evidence: Optional[List[Dict[str, Any]]] = None,
    limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Every tool returns: what was found, the evidence behind it, and what it can't tell you."""
    return {
        "tool": tool,
        "target": str(target),
        "findings": findings,
        "evidence": evidence or [],
        "limitations": limitations or [],
    }
