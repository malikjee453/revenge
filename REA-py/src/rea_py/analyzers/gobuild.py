"""Go build info (Go 1.18+ inline-string format): compiler version, module path, dependencies, build settings."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..registry import tool
from ..util import ReaError, open_mmap, result

MAGIC = b"\xff Go buildinf:"


def _uvarint(buf: Any, pos: int) -> Tuple[int, int]:
    shift = value = 0
    while True:
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ReaError("Bad varint in Go build info")


def parse_modinfo(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": None, "main_module": None, "dependencies": [], "replacements": [], "build_settings": {}}
    last_dep = None
    for line in text.splitlines():
        parts = line.split("\t")
        kind = parts[0]
        if kind == "path" and len(parts) > 1:
            out["path"] = parts[1]
        elif kind == "mod" and len(parts) > 1:
            out["main_module"] = {"path": parts[1], "version": parts[2] if len(parts) > 2 else None}
        elif kind == "dep" and len(parts) > 1:
            last_dep = {"path": parts[1], "version": parts[2] if len(parts) > 2 else None}
            out["dependencies"].append(last_dep)
        elif kind == "=>" and len(parts) > 1 and last_dep is not None:
            out["replacements"].append({"from": last_dep["path"], "to": parts[1], "version": parts[2] if len(parts) > 2 else None})
        elif kind == "build" and len(parts) > 1 and "=" in parts[1]:
            k, v = parts[1].split("=", 1)
            out["build_settings"][k] = v
    return out


@tool("inspect_go_buildinfo", "Read the Go build info embedded in a Go binary (compiler version, module, dependencies, build flags) without needing Go installed.")
def inspect_go_buildinfo(path: str):
    with open_mmap(path) as m:
        idx = m.find(MAGIC)
        while idx != -1 and idx % 16 != 0:
            idx = m.find(MAGIC, idx + 1)
        if idx == -1:
            return result("inspect_go_buildinfo", path, {"is_go_binary": False}, [],
                          ["No Go build-info header found. Stripped, packed, or pre-Go-1.13 binaries may not carry one."])
        ptr_size, flags = m[idx + 14], m[idx + 15]
        if not flags & 2:
            return result("inspect_go_buildinfo", path,
                          {"is_go_binary": True, "format": "pointer-based (Go < 1.18)", "offset": idx},
                          [{"kind": "buildinfo-header", "offset": idx}],
                          ["Pre-1.18 binaries store build info behind pointers into the data segment; this port decodes only the inline format."])
        pos = idx + 32
        n, pos = _uvarint(m, pos)
        version = bytes(m[pos : pos + n]).decode("utf-8", "replace")
        pos += n
        n, pos = _uvarint(m, pos)
        mod = bytes(m[pos : pos + n])
    if len(mod) >= 33:
        mod = mod[16:-16]
    info = parse_modinfo(mod.decode("utf-8", "replace"))
    deps: List[Dict[str, Any]] = info.pop("dependencies")
    return result(
        "inspect_go_buildinfo", path,
        {"is_go_binary": True, "go_version": version, "pointer_size": ptr_size, **info,
         "dependency_count": len(deps), "dependencies": deps[:500]},
        [{"kind": "buildinfo-header", "offset": idx, "detail": "Magic '\\xff Go buildinf:' at a 16-byte aligned offset."}],
        ["Dependencies reflect what the linker recorded; vendored or stripped builds may omit them.",
         "Dependency list capped at 500 entries."],
    )
