"""String extraction with offsets."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..registry import tool
from ..util import open_mmap, result

MAX_RESULTS_CAP = 5000


@tool(
    "extract_strings",
    "Extract printable ASCII (and optionally UTF-16LE) strings with file offsets, optionally filtered by a substring.",
    {
        "min_length": {"type": "integer", "description": "Minimum string length (default 6)."},
        "max_results": {"type": "integer", "description": f"Maximum strings returned (default 500, cap {MAX_RESULTS_CAP})."},
        "contains": {"type": "string", "description": "Only keep strings containing this text (case-insensitive)."},
        "utf16": {"type": "boolean", "description": "Also extract UTF-16LE strings (default false)."},
    },
)
def extract_strings(path: str, min_length: int = 6, max_results: int = 500, contains: str = "", utf16: bool = False):
    min_length = max(3, min(min_length, 512))
    max_results = max(1, min(max_results, MAX_RESULTS_CAP))
    needle = contains.lower()
    out: List[Dict[str, Any]] = []
    truncated = False
    with open_mmap(path) as m:
        patterns = [("ascii", re.compile(rb"[\x20-\x7e]{%d,}" % min_length))]
        if utf16:
            patterns.append(("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)))
        for enc, rx in patterns:
            for mt in rx.finditer(m):
                raw = mt.group(0)
                text = raw.decode("ascii") if enc == "ascii" else raw.decode("utf-16le")
                if needle and needle not in text.lower():
                    continue
                if len(out) >= max_results:
                    truncated = True
                    break
                out.append({"offset": mt.start(), "encoding": enc, "text": text[:512]})
        size = len(m)
    out.sort(key=lambda s: s["offset"])
    return result(
        "extract_strings", path,
        {"count": len(out), "truncated": truncated, "file_size": size, "strings": out},
        [{"kind": "byte-scan", "detail": f"Regex scan for runs of >= {min_length} printable characters."}],
        ["Strings are raw byte runs, not decoded symbols; packed or encrypted data hides content.",
         "Individual strings are truncated at 512 characters."],
    )
