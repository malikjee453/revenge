"""PE inspection: headers, sections, imports, hardening flags and certificate presence."""
from __future__ import annotations

import datetime
import struct
from typing import Any, Dict, List, Optional

from ..registry import tool
from ..util import ReaError, cstring, open_mmap, result

MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64"}
SUBSYSTEMS = {1: "native", 2: "windows-gui", 3: "windows-console", 9: "windows-ce-gui", 10: "efi-application"}
DIRS = ["export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
        "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr", "reserved"]
MAX_IMPORT_DLLS = 256
MAX_FUNCS_PER_DLL = 2048


def parse_pe(m: Any) -> Dict[str, Any]:
    if bytes(m[:2]) != b"MZ":
        raise ReaError("Not a PE file (missing MZ)")
    (lfanew,) = struct.unpack_from("<I", m, 0x3C)
    if bytes(m[lfanew : lfanew + 4]) != b"PE\0\0":
        raise ReaError("Not a PE file (missing PE signature)")
    machine, nsec, ts, _symptr, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", m, lfanew + 4)
    opt = lfanew + 24
    magic = struct.unpack_from("<H", m, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ReaError("Unknown optional header magic")
    pe32plus = magic == 0x20B
    entry = struct.unpack_from("<I", m, opt + 16)[0]
    image_base = struct.unpack_from("<Q" if pe32plus else "<I", m, opt + (24 if pe32plus else 28))[0]
    subsystem, dll_chars = struct.unpack_from("<HH", m, opt + 68)
    ndirs_off = opt + (108 if pe32plus else 92)
    ndirs = min(struct.unpack_from("<I", m, ndirs_off)[0], 16)
    dirs: Dict[str, Dict[str, int]] = {}
    for i in range(ndirs):
        rva, size = struct.unpack_from("<II", m, ndirs_off + 4 + i * 8)
        if rva or size:
            dirs[DIRS[i]] = {"rva_or_offset": rva, "size": size}

    sec_off = opt + opt_size
    sections: List[Dict[str, Any]] = []
    for i in range(min(nsec, 96)):
        name, vsize, vaddr, rawsize, rawptr, *_rest, schars = struct.unpack_from("<8sIIIIIIHHI", m, sec_off + i * 40)
        sections.append({
            "name": name.rstrip(b"\0").decode("ascii", "replace"), "virtual_size": vsize,
            "virtual_address": vaddr, "raw_size": rawsize, "raw_offset": rawptr,
            "executable": bool(schars & 0x20000000), "writable": bool(schars & 0x80000000),
            "readable": bool(schars & 0x40000000),
        })

    def rva2off(rva: int) -> Optional[int]:
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= rva < s["virtual_address"] + span:
                return s["raw_offset"] + (rva - s["virtual_address"])
        return rva if rva < (sections[0]["raw_offset"] if sections else 0) else None

    imports: List[Dict[str, Any]] = []
    if "import" in dirs:
        base = rva2off(dirs["import"]["rva_or_offset"])
        tsz = 8 if pe32plus else 4
        ordflag = 1 << (63 if pe32plus else 31)
        for i in range(MAX_IMPORT_DLLS):
            if base is None:
                break
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", m, base + i * 20)
            if name_rva == 0 and ft == 0:
                break
            name_off = rva2off(name_rva)
            dll = cstring(m, name_off, 256) if name_off is not None else "?"
            thunk = rva2off(oft or ft)
            funcs: List[Any] = []
            j = 0
            while thunk is not None and j < MAX_FUNCS_PER_DLL:
                (val,) = struct.unpack_from("<Q" if pe32plus else "<I", m, thunk + j * tsz)
                if val == 0:
                    break
                if val & ordflag:
                    funcs.append({"ordinal": val & 0xFFFF})
                else:
                    hn = rva2off(val & 0x7FFFFFFF)
                    funcs.append(cstring(m, hn + 2, 256) if hn is not None else "?")
                j += 1
            imports.append({"dll": dll, "iat_rva": ft, "functions": funcs})

    exports: List[Dict[str, Any]] = []
    export_name = None
    if "export" in dirs:
        d_rva, d_size = dirs["export"]["rva_or_offset"], dirs["export"]["size"]
        eo = rva2off(d_rva)
        if eo is not None:
            (_c, _t, _maj, _min, name_rva, base, nfunc, nnames, af, an, ao) = struct.unpack_from("<IIHHIIIIIII", m, eo)
            no = rva2off(name_rva)
            export_name = cstring(m, no, 256) if no is not None else None
            fo, nmo, oo = rva2off(af), rva2off(an), rva2off(ao)
            named: Dict[int, str] = {}
            if nmo is not None and oo is not None:
                for i in range(min(nnames, 4096)):
                    (nr,) = struct.unpack_from("<I", m, nmo + i * 4)
                    (idx,) = struct.unpack_from("<H", m, oo + i * 2)
                    n2 = rva2off(nr)
                    if n2 is not None:
                        named[idx] = cstring(m, n2, 256)
            if fo is not None:
                for i in range(min(nfunc, 4096)):
                    (frva,) = struct.unpack_from("<I", m, fo + i * 4)
                    if frva == 0:
                        continue
                    entry: Dict[str, Any] = {"ordinal": base + i, "name": named.get(i), "rva": frva}
                    if d_rva <= frva < d_rva + d_size:
                        f2 = rva2off(frva)
                        entry["forwarded_to"] = cstring(m, f2, 256) if f2 is not None else None
                    exports.append(entry)

    hardening = {
        "aslr_dynamic_base": bool(dll_chars & 0x40),
        "high_entropy_va": bool(dll_chars & 0x20),
        "dep_nx_compat": bool(dll_chars & 0x100),
        "no_seh": bool(dll_chars & 0x400),
        "control_flow_guard": bool(dll_chars & 0x4000),
        "force_integrity": bool(dll_chars & 0x80),
        "app_container": bool(dll_chars & 0x1000),
        "relocations_stripped": bool(chars & 0x1),
    }
    return {
        "architecture": MACHINES.get(machine, hex(machine)),
        "pe_format": "PE32+" if pe32plus else "PE32",
        "timestamp": datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat() if ts else None,
        "is_dll": bool(chars & 0x2000),
        "subsystem": SUBSYSTEMS.get(subsystem, subsystem),
        "entry_rva": entry,
        "image_base": image_base,
        "data_directories": dirs,
        "sections": sections,
        "imports": imports,
        "has_authenticode_signature_entry": "security" in dirs,
        "is_dotnet": "clr" in dirs,
        "has_delay_imports": "delay_import" in dirs,
        "export_name": export_name,
        "export_count": len(exports),
        "exports": exports,
        "hardening": hardening,
    }


@tool("inspect_pe", "Inspect a Windows PE (EXE/DLL): headers, sections, import table, hardening flags (ASLR, DEP, CFG) and .NET/signature indicators.")
def inspect_pe(path: str):
    with open_mmap(path) as m:
        info = parse_pe(m)
    return result(
        "inspect_pe", path, info,
        [{"kind": "pe-headers", "detail": "Parsed DOS/COFF/optional headers, section table and import directory."}],
        [
            f"At most {MAX_IMPORT_DLLS} imported DLLs and {MAX_FUNCS_PER_DLL} functions per DLL are listed.",
            "Delay-load imports are flagged but not enumerated; at most 4096 exports are listed.",
            "Authenticode presence is reported; the PKCS#7 signature is not parsed or verified.",
            "Timestamps can be forged or zeroed by reproducible builds; do not treat as a build date.",
        ],
    )
