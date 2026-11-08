"""Embedded-file carving scan (binwalk-style signature search). Reports offsets only; nothing is extracted."""
from __future__ import annotations

from typing import Any, Dict, List

from ..registry import tool
from ..util import open_mmap, result

SIGNATURES = [
    ("zip", b"PK\x03\x04"), ("gzip", b"\x1f\x8b\x08"), ("bzip2", b"BZh"), ("xz", b"\xfd7zXZ\x00"),
    ("7z", b"7z\xbc\xaf\x27\x1c"), ("rar", b"Rar!\x1a\x07"), ("png", b"\x89PNG\r\n\x1a\n"), ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF8"), ("pdf", b"%PDF-"), ("elf", b"\x7fELF"), ("sqlite", b"SQLite format 3\x00"),
    ("pem", b"-----BEGIN "), ("pe", b"MZ"), ("wasm", b"\0asm\x01\0\0\0"),
]
PER_TYPE_CAP = 50
TOTAL_CAP = 300


def _valid(name: str, m, i: int) -> bool:
    if name == "pe":
        if i + 0x40 > len(m):
            return False
        e = int.from_bytes(m[i + 0x3C : i + 0x40], "little")
        return 0 < e < 0x1000 and bytes(m[i + e : i + e + 4]) == b"PE\0\0"
    if name == "elf":
        return i + 6 <= len(m) and m[i + 4] in (1, 2) and m[i + 5] in (1, 2)
    if name == "gzip":
        return i + 4 <= len(m) and m[i + 3] & 0xE0 == 0
    return True


@tool("find_embedded_files", "Scan for embedded files by signature (zip, gzip, png, elf, pe, sqlite, pdf, pem...) and report offsets.")
def find_embedded_files(path: str):
    hits: List[Dict[str, Any]] = []
    with open_mmap(path) as m:
        size = len(m)
        for name, magic in SIGNATURES:
            count, pos = 0, m.find(magic)
            while pos != -1 and count < PER_TYPE_CAP:
                if _valid(name, m, pos):
                    hits.append({"type": name, "offset": pos, "at_file_start": pos == 0})
                    count += 1
                pos = m.find(magic, pos + 1)
    hits.sort(key=lambda h: h["offset"])
    inner = [h for h in hits if not h["at_file_start"]]
    return result(
        "find_embedded_files", path,
        {"file_size": size, "hit_count": len(hits), "embedded_beyond_start": len(inner), "hits": hits[:TOTAL_CAP]},
        [{"kind": "signature-scan", "detail": "Byte-signature search with light validation for PE, ELF and gzip."}],
        ["A signature match is a lead, not proof: random data can contain these bytes.",
         f"At most {PER_TYPE_CAP} hits per type and {TOTAL_CAP} overall are listed.", "Nothing is carved or extracted."],
    )
