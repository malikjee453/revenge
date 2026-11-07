"""Identify a file's format from magic bytes (no execution, no parsing beyond headers)."""
from __future__ import annotations

import struct
from typing import Any, Dict

from ..registry import tool
from ..util import open_mmap, result

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": "macho-32-be",
    b"\xfe\xed\xfa\xcf": "macho-64-be",
    b"\xce\xfa\xed\xfe": "macho-32-le",
    b"\xcf\xfa\xed\xfe": "macho-64-le",
}


def detect(m: Any) -> Dict[str, Any]:
    size = len(m)
    head = bytes(m[:16])
    if head.startswith(b"\x7fELF"):
        return {"format": "elf"}
    if head.startswith(b"MZ") and size >= 0x40:
        (e_lfanew,) = struct.unpack_from("<I", m, 0x3C)
        if e_lfanew + 4 <= size and bytes(m[e_lfanew : e_lfanew + 4]) == b"PE\0\0":
            return {"format": "pe"}
        return {"format": "dos-mz"}
    if head[:4] in MACHO_MAGICS:
        return {"format": "macho", "variant": MACHO_MAGICS[head[:4]]}
    if head[:4] == b"\xca\xfe\xba\xbe":
        (n,) = struct.unpack_from(">I", m, 4)
        # Java class files share this magic; fat Mach-O has a small arch count.
        return {"format": "macho-fat"} if 0 < n < 20 else {"format": "java-class"}
    if head.startswith(b"SQLite format 3\0"):
        return {"format": "sqlite"}
    if head.startswith(b"GGUF"):
        return {"format": "gguf"}
    if head.startswith(b"\0asm"):
        return {"format": "wasm"}
    if head.startswith(b"%PDF"):
        return {"format": "pdf"}
    if head.startswith(b"PK\x03\x04"):
        return {"format": "zip"}
    if size >= 17 and struct.unpack_from("<I", m, 0)[0] == 4 and m[16:17] == b"{":
        return {"format": "asar"}
    if size >= 9:
        (hlen,) = struct.unpack_from("<Q", m, 0)
        if 2 <= hlen < min(size, 100 * 1024 * 1024) and m[8:9] == b"{":
            return {"format": "safetensors"}
    text = bytes(m[: min(size, 4096)]).lstrip()
    if text.startswith(b"{") and b'"log"' in text and b'"entries"' in bytes(m[: min(size, 65536)]):
        return {"format": "har"}
    return {"format": "unknown"}


@tool("detect_file_type", "Identify a file's format from its magic bytes (ELF, PE, Mach-O, APK/ZIP, ASAR, SQLite, GGUF, safetensors, HAR, WASM...).")
def detect_file_type(path: str):
    with open_mmap(path) as m:
        info = detect(m)
        size = len(m)
    return result(
        "detect_file_type",
        path,
        {**info, "size_bytes": size},
        [{"kind": "magic-bytes", "detail": "Format decided from the first bytes of the file."}],
        ["Detection is by header only; a matching header does not prove the file is well-formed."],
    )
