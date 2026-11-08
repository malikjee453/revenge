"""File fingerprint: hashes, entropy map and packer/protector markers."""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Any, Dict, List

from ..registry import tool
from ..util import open_mmap, result

MAX_BLOCKS = 256
HIGH_ENTROPY = 7.2
PACKER_MARKERS = [
    (b"UPX!", "UPX"), (b"UPX0", "UPX section"), (b"PyInstaller", "PyInstaller"), (b"MEIPASS", "PyInstaller"),
    (b".vmp0", "VMProtect section"), (b".themida", "Themida section"), (b"ASPack", "ASPack"),
    (b"MPRESS1", "MPRESS"), (b"Enigma protector", "Enigma Protector"), (b"Nuitka", "Nuitka"), (b"py2exe", "py2exe"),
]


def _entropy(block: bytes) -> float:
    if not block:
        return 0.0
    n = len(block)
    return -sum(c / n * math.log2(c / n) for c in Counter(block).values())


@tool("fingerprint_file", "Compute MD5/SHA-1/SHA-256, a block entropy map, and packer/protector markers (UPX, PyInstaller, VMProtect, Themida...).",
      {"block_size": {"type": "integer", "description": "Entropy block size in bytes (default 65536)."}})
def fingerprint_file(path: str, block_size: int = 65536):
    block_size = max(256, min(block_size, 16 * 1024 * 1024))
    with open_mmap(path) as m:
        size = len(m)
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        for i in range(0, size, 4 * 1024 * 1024):
            chunk = m[i : i + 4 * 1024 * 1024]
            md5.update(chunk), sha1.update(chunk), sha256.update(chunk)
        nblocks = (size + block_size - 1) // block_size
        stride = max(1, nblocks // MAX_BLOCKS)
        sampled: List[Dict[str, Any]] = []
        for b in range(0, nblocks, stride):
            off = b * block_size
            sampled.append({"offset": off, "entropy": round(_entropy(bytes(m[off : off + block_size])), 3)})
        packers = sorted({label for needle, label in PACKER_MARKERS if m.find(needle) != -1})
    mean = sum(s["entropy"] for s in sampled) / len(sampled)
    high = [s for s in sampled if s["entropy"] >= HIGH_ENTROPY]
    hints = []
    if mean >= HIGH_ENTROPY:
        hints.append("Overall entropy is very high: the file is likely compressed, encrypted or packed.")
    elif high:
        hints.append(f"{len(high)} sampled block(s) have entropy >= {HIGH_ENTROPY}: possible embedded compressed or encrypted data.")
    return result(
        "fingerprint_file", path,
        {"size_bytes": size, "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(),
         "mean_entropy": round(mean, 3), "block_size": block_size, "blocks_sampled": len(sampled),
         "high_entropy_blocks": high[:50], "packer_markers": packers, "hints": hints,
         "entropy_map": sampled[:MAX_BLOCKS]},
        [{"kind": "hash+entropy", "detail": "Hashes over the full file; Shannon entropy over evenly spaced blocks."}],
        ["Entropy is a heuristic: media, archives and encrypted data all score high, and packers can lower it deliberately.",
         "Packer markers are string matches; their absence does not prove a file is unpacked.",
         f"At most {MAX_BLOCKS} blocks are sampled."],
    )
