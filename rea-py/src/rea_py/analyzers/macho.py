"""Thin and fat Mach-O inspection."""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from ..registry import tool
from ..util import ReaError, cstring, open_mmap, result

CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64"}
FILETYPE = {1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle", 10: "dsym"}
LC_SEGMENT, LC_SEGMENT_64, LC_UUID, LC_CODE_SIGNATURE, LC_MAIN, LC_ENCRYPTION_INFO_64 = 0x1, 0x19, 0x1B, 0x1D, 0x80000028, 0x2C
DYLIB_CMDS = {0xC: "load", 0x80000018: "load_weak", 0x1F: "reexport", 0x8000001F: "lazy_load"}
RPATH = 0x8000001C
MH_PIE, MH_NO_HEAP_EXEC, MH_ALLOW_STACK_EXEC = 0x200000, 0x1000000, 0x20000
MAX_CMDS = 1024


def _thin(m: Any, base: int) -> Dict[str, Any]:
    magic = bytes(m[base : base + 4])
    big = magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    if not big and magic not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        raise ReaError("Not a Mach-O slice")
    e = ">" if big else "<"
    cputype, _sub, ftype, ncmds, _sz, flags = struct.unpack_from(e + "iiIIII", m, base + 4)
    cputype &= 0xFFFFFFFF
    pos = base + (32 if is64 else 28)
    info: Dict[str, Any] = {
        "bits": 64 if is64 else 32, "endianness": "big" if big else "little",
        "cpu": CPU.get(cputype, hex(cputype)), "file_type": FILETYPE.get(ftype, ftype),
        "uuid": None, "segments": [], "dylibs": [], "rpaths": [], "entry_offset": None,
        "has_code_signature": False, "is_encrypted": False,
    }
    for _ in range(min(ncmds, MAX_CMDS)):
        cmd, cmdsize = struct.unpack_from(e + "II", m, pos)
        if cmdsize < 8:
            raise ReaError("Corrupt load command size")
        if cmd == LC_UUID:
            h = bytes(m[pos + 8 : pos + 24]).hex()
            info["uuid"] = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
            name = bytes(m[pos + 8 : pos + 24]).rstrip(b"\0").decode("ascii", "replace")
            if cmd == LC_SEGMENT_64:
                va, vsz, off, fsz, maxp, initp, nsects = struct.unpack_from(e + "QQQQiiI", m, pos + 24)
            else:
                va, vsz, off, fsz, maxp, initp, nsects = struct.unpack_from(e + "IIIIiiI", m, pos + 24)
            info["segments"].append({"name": name, "vmaddr": va, "vmsize": vsz, "fileoff": off,
                                     "filesize": fsz, "maxprot": maxp, "initprot": initp, "sections": nsects})
        elif cmd in DYLIB_CMDS:
            (noff,) = struct.unpack_from(e + "I", m, pos + 8)
            info["dylibs"].append({"kind": DYLIB_CMDS[cmd], "name": cstring(m, pos + noff, 1024)})
        elif cmd == RPATH:
            (noff,) = struct.unpack_from(e + "I", m, pos + 8)
            info["rpaths"].append(cstring(m, pos + noff, 1024))
        elif cmd == LC_MAIN:
            info["entry_offset"] = struct.unpack_from(e + "Q", m, pos + 8)[0]
        elif cmd == LC_CODE_SIGNATURE:
            info["has_code_signature"] = True
        elif cmd == LC_ENCRYPTION_INFO_64:
            _off, _size, cryptid = struct.unpack_from(e + "III", m, pos + 8)
            info["is_encrypted"] = cryptid != 0
        pos += cmdsize
    info["hardening"] = {
        "pie": bool(flags & MH_PIE),
        "no_heap_execution": bool(flags & MH_NO_HEAP_EXEC),
        "stack_execution_allowed": bool(flags & MH_ALLOW_STACK_EXEC),
        "code_signature_present": info["has_code_signature"],
    }
    return info


@tool("inspect_macho", "Inspect a Mach-O binary (thin or fat): CPU, file type, UUID, segments, linked dylibs, rpaths, PIE and code-signature indicators.")
def inspect_macho(path: str):
    with open_mmap(path) as m:
        magic = bytes(m[:4])
        slices: List[Dict[str, Any]] = []
        if magic == b"\xca\xfe\xba\xbe":
            (n,) = struct.unpack_from(">I", m, 4)
            if not 0 < n < 20:
                raise ReaError("Not a fat Mach-O (looks like a Java class file)")
            for i in range(n):
                cpu, _sub, off, size, _align = struct.unpack_from(">iiIII", m, 8 + i * 20)
                s = _thin(m, off)
                s["slice_offset"], s["slice_size"] = off, size
                slices.append(s)
            findings: Dict[str, Any] = {"fat": True, "slices": slices}
        else:
            findings = {"fat": False, "slices": [_thin(m, 0)]}
    return result(
        "inspect_macho", path, findings,
        [{"kind": "macho-load-commands", "detail": "Parsed mach_header and load commands."}],
        [
            "Symbol tables, Objective-C/Swift metadata and entitlements are not decoded.",
            "Code-signature presence is reported; the signature is not validated.",
        ],
    )
