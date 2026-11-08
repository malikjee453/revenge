"""WebAssembly module structure: sections, imports, exports."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..registry import tool
from ..util import ReaError, open_mmap, result

SECTIONS = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global", 7: "export",
            8: "start", 9: "element", 10: "code", 11: "data", 12: "datacount", 13: "tag"}
KINDS = ["func", "table", "memory", "global", "tag"]
CAP = 2000


def _leb(m: Any, pos: int) -> Tuple[int, int]:
    result_, shift = 0, 0
    while True:
        b = m[pos]
        pos += 1
        result_ |= (b & 0x7F) << shift
        if not b & 0x80:
            return result_, pos
        shift += 7
        if shift > 70:
            raise ReaError("Bad LEB128")


def _name(m: Any, pos: int) -> Tuple[str, int]:
    n, pos = _leb(m, pos)
    return bytes(m[pos : pos + n]).decode("utf-8", "replace"), pos + n


def _limits(m: Any, pos: int) -> int:
    flag = m[pos]
    _, pos = _leb(m, pos + 1)
    if flag & 1:
        _, pos = _leb(m, pos)
    return pos


@tool("inspect_wasm", "Inspect a WebAssembly module: sections, imports, exports, function counts and custom section names.")
def inspect_wasm(path: str):
    with open_mmap(path) as m:
        if bytes(m[:4]) != b"\0asm":
            raise ReaError("Not a WebAssembly module")
        version = int.from_bytes(m[4:8], "little")
        pos, n = 8, len(m)
        secs: List[Dict[str, Any]] = []
        imports: List[Dict[str, Any]] = []
        exports: List[Dict[str, Any]] = []
        custom: List[str] = []
        counts: Dict[str, int] = {}
        while pos < n and len(secs) < 256:
            sid = m[pos]
            size, body = _leb(m, pos + 1)
            end = body + size
            if end > n:
                raise ReaError("Section extends past end of file")
            secs.append({"id": sid, "name": SECTIONS.get(sid, str(sid)), "offset": pos, "size": size})
            if sid == 0:
                custom.append(_name(m, body)[0])
            elif sid in (3, 10):
                counts["functions_declared" if sid == 3 else "function_bodies"] = _leb(m, body)[0]
            elif sid == 2:
                cnt, p = _leb(m, body)
                for _ in range(min(cnt, CAP)):
                    mod, p = _name(m, p)
                    nm, p = _name(m, p)
                    kind = m[p]
                    p += 1
                    if kind in (0, 4):
                        _, p = _leb(m, p + (1 if kind == 4 else 0))
                    elif kind == 1:
                        p = _limits(m, p + 1)
                    elif kind == 2:
                        p = _limits(m, p)
                    elif kind == 3:
                        p += 2
                    imports.append({"module": mod, "name": nm, "kind": KINDS[kind] if kind < 5 else kind})
            elif sid == 7:
                cnt, p = _leb(m, body)
                for _ in range(min(cnt, CAP)):
                    nm, p = _name(m, p)
                    kind = m[p]
                    idx, p = _leb(m, p + 1)
                    exports.append({"name": nm, "kind": KINDS[kind] if kind < 5 else kind, "index": idx})
            pos = end
    return result(
        "inspect_wasm", path,
        {"version": version, "sections": secs, "counts": counts, "import_count": len(imports), "imports": imports,
         "export_count": len(exports), "exports": exports, "custom_sections": custom,
         "has_name_section": "name" in custom, "has_source_map": "sourceMappingURL" in custom},
        [{"kind": "wasm-sections", "detail": "Walked the section list and decoded import/export sections."}],
        ["Function bodies are not disassembled (use wasm-objdump or wasm2wat).", f"At most {CAP} imports/exports are listed."],
    )
