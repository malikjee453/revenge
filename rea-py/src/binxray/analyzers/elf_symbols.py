"""ELF symbol tables (.dynsym / .symtab): imported and exported functions and objects."""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from ..registry import tool
from ..util import ReaError, cstring, open_mmap, result
from .elf import parse_elf

TYPES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS", 10: "GNU_IFUNC"}
BINDS = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
CAP = 2000


@tool("inspect_elf_symbols", "List ELF symbols: imported (undefined) and exported (defined) functions/objects from .dynsym, plus .symtab if the binary is not stripped.")
def inspect_elf_symbols(path: str):
    with open_mmap(path) as m:
        info = parse_elf(m)
        is64 = info["class"] == 64
        e = "<" if info["endianness"] == "little" else ">"
        secs = info["sections"]
        tables: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for s in secs:
            if s["type"] not in ("DYNSYM", "SYMTAB"):
                continue
            if s["link"] >= len(secs):
                raise ReaError("Symbol table links to a missing string table")
            stroff = secs[s["link"]]["offset"]
            ent = 24 if is64 else 16
            rows: Dict[str, List[Dict[str, Any]]] = {"imported": [], "exported": [], "local": []}
            for i in range(1, min(s["size"] // ent, 200000)):
                o = s["offset"] + i * ent
                if is64:
                    name, ino, _oth, shndx, value, size = struct.unpack_from(e + "IBBHQQ", m, o)
                else:
                    name, value, size, ino, _oth, shndx = struct.unpack_from(e + "IIIBBH", m, o)
                row = {"name": cstring(m, stroff + name, 512), "type": TYPES.get(ino & 0xF, ino & 0xF),
                       "bind": BINDS.get(ino >> 4, ino >> 4), "value": value, "size": size}
                if not row["name"]:
                    continue
                bucket = "imported" if shndx == 0 else ("exported" if ino >> 4 in (1, 2) else "local")
                if len(rows[bucket]) < CAP:
                    rows[bucket].append(row)
            tables[s["name"]] = rows
    summary = {t: {k: len(v) for k, v in r.items()} for t, r in tables.items()}
    return result(
        "inspect_elf_symbols", path,
        {"tables_found": list(tables), "summary": summary, "stripped": ".symtab" not in tables, "symbols": tables},
        [{"kind": "elf-symtab", "detail": "Decoded Elf_Sym entries using each table's linked string section."}],
        [f"At most {CAP} symbols per bucket are listed.", "Stripped binaries have no .symtab; only dynamic symbols remain.",
         "Names are as stored (C++/Rust names are mangled)."],
    )
