"""ELF inspection: header, segments, sections, dynamic table, notes and hardening flags."""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

from ..registry import tool
from ..util import ReaError, cstring, open_mmap, result

MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0xF3: "RISC-V",
    0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390", 0x2A: "SuperH",
}
ETYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
PT = {
    1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 6: "PT_PHDR", 7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}
SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC",
       7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM"}
DT_NEEDED, DT_STRTAB, DT_SONAME, DT_RPATH, DT_BIND_NOW = 1, 5, 14, 15, 24
DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 29, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000
MAX_SECTIONS = 512
MAX_SEGMENTS = 256


def _flags(p_flags: int) -> str:
    return ("R" if p_flags & 4 else "-") + ("W" if p_flags & 2 else "-") + ("X" if p_flags & 1 else "-")


def parse_elf(m: Any) -> Dict[str, Any]:
    if bytes(m[:4]) != b"\x7fELF":
        raise ReaError("Not an ELF file")
    cls, data_enc = m[4], m[5]
    if cls not in (1, 2) or data_enc not in (1, 2):
        raise ReaError("Unsupported ELF class or endianness")
    is64 = cls == 2
    e = "<" if data_enc == 1 else ">"
    if is64:
        hdr = struct.unpack_from(e + "HHIQQQIHHHHHH", m, 16)
    else:
        hdr = struct.unpack_from(e + "HHIIIIIHHHHHH", m, 16)
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, e_flags, _ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = hdr

    # Program headers
    segments: List[Dict[str, Any]] = []
    for i in range(min(e_phnum, MAX_SEGMENTS)):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_off, p_va, _pa, p_fsz, p_msz, p_align = struct.unpack_from(e + "IIQQQQQQ", m, off)
        else:
            p_type, p_off, p_va, _pa, p_fsz, p_msz, p_flags, p_align = struct.unpack_from(e + "IIIIIIII", m, off)
        segments.append({
            "type": PT.get(p_type, hex(p_type)), "_type": p_type, "flags": _flags(p_flags),
            "offset": p_off, "vaddr": p_va, "filesz": p_fsz, "memsz": p_msz, "align": p_align,
        })
    loads = [(s["offset"], s["vaddr"], s["filesz"]) for s in segments if s["_type"] == 1]

    def v2o(va: int) -> Optional[int]:
        for off, base, fsz in loads:
            if base <= va < base + fsz:
                return off + (va - base)
        return None

    interp = None
    for s in segments:
        if s["_type"] == 3:
            interp = cstring(m, s["offset"], min(s["filesz"], 512) or 512)

    # Dynamic table
    dyn: Dict[int, List[int]] = {}
    for s in segments:
        if s["_type"] == 2:
            ent = 16 if is64 else 8
            fmt = e + ("QQ" if is64 else "II")
            for j in range(min(s["filesz"] // ent, 4096)):
                tag, val = struct.unpack_from(fmt, m, s["offset"] + j * ent)
                if tag == 0:
                    break
                dyn.setdefault(tag, []).append(val)
    strtab = v2o(dyn[DT_STRTAB][0]) if DT_STRTAB in dyn else None

    def dstr(val: int) -> Optional[str]:
        return cstring(m, strtab + val) if strtab is not None else None

    needed = [dstr(v) for v in dyn.get(DT_NEEDED, [])] if strtab is not None else []
    soname = dstr(dyn[DT_SONAME][0]) if DT_SONAME in dyn and strtab is not None else None
    rpath = [dstr(v) for v in dyn.get(DT_RPATH, [])] if strtab is not None else []
    runpath = [dstr(v) for v in dyn.get(DT_RUNPATH, [])] if strtab is not None else []

    # Sections
    sections: List[Dict[str, Any]] = []
    if e_shoff and e_shnum:
        raw = []
        for i in range(min(e_shnum, MAX_SECTIONS)):
            off = e_shoff + i * e_shentsize
            if is64:
                nm, ty, fl, ad, of, sz, *_ = struct.unpack_from(e + "IIQQQQIIQQ", m, off)
            else:
                nm, ty, fl, ad, of, sz, *_ = struct.unpack_from(e + "IIIIIIIIII", m, off)
            raw.append((nm, ty, fl, ad, of, sz))
        names_off = raw[e_shstrndx][4] if e_shstrndx < len(raw) else None
        for nm, ty, fl, ad, of, sz in raw:
            sections.append({
                "name": cstring(m, names_off + nm, 256) if names_off is not None else "",
                "type": SHT.get(ty, hex(ty)), "addr": ad, "offset": of, "size": sz,
                "flags": ("W" if fl & 1 else "") + ("A" if fl & 2 else "") + ("X" if fl & 4 else ""),
            })

    # Notes
    notes: List[Dict[str, Any]] = []
    for s in segments:
        if s["_type"] != 4:
            continue
        pos, end = s["offset"], s["offset"] + s["filesz"]
        while pos + 12 <= end and len(notes) < 64:
            namesz, descsz, ntype = struct.unpack_from(e + "III", m, pos)
            name = bytes(m[pos + 12 : pos + 12 + namesz]).rstrip(b"\0").decode("ascii", "replace")
            d0 = pos + 12 + ((namesz + 3) & ~3)
            desc = bytes(m[d0 : d0 + descsz])
            note: Dict[str, Any] = {"owner": name, "type": ntype, "desc_size": descsz}
            if name == "GNU" and ntype == 3:
                note["build_id"] = desc.hex()
            notes.append(note)
            pos = d0 + ((descsz + 3) & ~3)

    stack = next((s for s in segments if s["_type"] == 0x6474E551), None)
    has_relro = any(s["_type"] == 0x6474E552 for s in segments)
    bind_now = (
        DT_BIND_NOW in dyn
        or any(v & DF_BIND_NOW for v in dyn.get(DT_FLAGS, []))
        or any(v & DF_1_NOW for v in dyn.get(DT_FLAGS_1, []))
    )
    pie_flag = any(v & DF_1_PIE for v in dyn.get(DT_FLAGS_1, []))
    if e_type == 3:
        pie = "pie-executable" if (interp or pie_flag) else "shared-object"
    else:
        pie = "no-pie" if e_type == 2 else "n/a"
    canary = bm = None
    for needle in (b"__stack_chk_fail", b"__stack_chk_guard"):
        if m.find(needle) != -1:
            canary = True
            break
    hardening = {
        "pie": pie,
        "nx": None if stack is None else ("X" not in stack["flags"]),
        "relro": "full" if has_relro and bind_now else ("partial" if has_relro else "none"),
        "bind_now": bind_now,
        "stack_canary_symbol_present": bool(canary),
    }
    for s in segments:
        s.pop("_type", None)
    return {
        "class": 64 if is64 else 32,
        "endianness": "little" if e == "<" else "big",
        "type": ETYPES.get(e_type, hex(e_type)),
        "machine": MACHINES.get(e_machine, hex(e_machine)),
        "entry": e_entry,
        "flags": e_flags,
        "interpreter": interp,
        "needed_libraries": needed,
        "soname": soname,
        "rpath": rpath,
        "runpath": runpath,
        "segments": segments,
        "sections": sections,
        "notes": notes,
        "hardening": hardening,
    }


@tool("inspect_elf", "Inspect an ELF binary: header, segments, sections, needed libraries, build-id notes and hardening flags (PIE, NX, RELRO).")
def inspect_elf(path: str):
    with open_mmap(path) as m:
        info = parse_elf(m)
    return result(
        "inspect_elf", path, info,
        [{"kind": "elf-header", "detail": "Parsed ELF header, program headers, section headers, PT_DYNAMIC and PT_NOTE."}],
        [
            f"Sections listed up to {MAX_SECTIONS} and segments up to {MAX_SEGMENTS}.",
            "Stack-canary status is a symbol-string heuristic: it shows the check function is referenced, not that every function is protected.",
            "Static analysis only; disassembly and decompilation are out of scope (use Ghidra, Hopper, IDA or Rizin).",
        ],
    )
