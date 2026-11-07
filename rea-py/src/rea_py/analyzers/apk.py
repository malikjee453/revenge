"""Android APK inspection: manifest (binary XML), DEX headers, native libraries, signing files and framework markers."""
from __future__ import annotations

import struct
import zipfile
from typing import Any, Dict, List, Optional

from ..registry import tool
from ..util import ReaError, resolve_file, result

MAX_ENTRIES = 50000
MAX_MANIFEST = 16 * 1024 * 1024


def _read_pool(d: bytes, off: int) -> List[str]:
    _t, hsize, _size, count, _styles, flags, strings_start, _ss = struct.unpack_from("<HHIIIIII", d, off)
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from(f"<{count}I", d, off + hsize)
    out = []
    for o in offs:
        p = off + strings_start + o
        if utf8:
            c = d[p]
            p += 2 if c & 0x80 else 1  # skip UTF-16 char count
            b = d[p]
            if b & 0x80:
                ln, p = ((b & 0x7F) << 8) | d[p + 1], p + 2
            else:
                ln, p = b, p + 1
            out.append(bytes(d[p : p + ln]).decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", d, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]
                p += 2
            out.append(bytes(d[p : p + n * 2]).decode("utf-16le", "replace"))
    return out


def parse_manifest(d: bytes) -> Dict[str, Any]:
    if len(d) < 8 or struct.unpack_from("<H", d, 0)[0] != 0x0003:
        raise ReaError("AndroidManifest.xml is not binary XML")
    pos = struct.unpack_from("<H", d, 2)[0]
    strings: List[str] = []
    info: Dict[str, Any] = {"package": None, "version_code": None, "version_name": None, "min_sdk": None,
                            "target_sdk": None, "permissions": [], "components": [], "debuggable": None, "allow_backup": None}
    stack: List[str] = []
    while pos + 8 <= len(d):
        ctype, hsize, size = struct.unpack_from("<HHI", d, pos)
        if size < 8:
            break
        if ctype == 0x0001:
            strings = _read_pool(d, pos)
        elif ctype == 0x0102 and strings:
            name_i, = struct.unpack_from("<I", d, pos + 20)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", d, pos + 24)
            tag = strings[name_i] if name_i < len(strings) else "?"
            attrs: Dict[str, Any] = {}
            for k in range(attr_count):
                a = pos + 16 + attr_start + k * attr_size
                _ns, an, raw, _vs, _r, dtype, data = struct.unpack_from("<IIIHBBI", d, a)
                key = strings[an] if an < len(strings) else "?"
                if dtype == 0x03:
                    val: Any = strings[data] if data < len(strings) else None
                elif dtype == 0x12:
                    val = bool(data)
                elif dtype in (0x10, 0x11):
                    val = data
                else:
                    val = strings[raw] if raw != 0xFFFFFFFF and raw < len(strings) else data
                attrs[key] = val
            stack.append(tag)
            if tag == "manifest":
                info["package"] = attrs.get("package")
                info["version_code"] = attrs.get("versionCode")
                info["version_name"] = attrs.get("versionName")
            elif tag == "uses-sdk":
                info["min_sdk"], info["target_sdk"] = attrs.get("minSdkVersion"), attrs.get("targetSdkVersion")
            elif tag == "uses-permission" and attrs.get("name"):
                info["permissions"].append(attrs["name"])
            elif tag == "application":
                info["debuggable"], info["allow_backup"] = attrs.get("debuggable"), attrs.get("allowBackup")
            elif tag in ("activity", "service", "receiver", "provider", "activity-alias"):
                info["components"].append({"type": tag, "name": attrs.get("name"), "exported": attrs.get("exported")})
        elif ctype == 0x0103 and stack:
            stack.pop()
        pos += size
    return info


@tool("inspect_apk", "Inspect an Android APK without running it: manifest (package, SDKs, permissions, components), DEX headers, native ABIs, signing files and framework markers (Flutter, React Native, Unity, Xamarin).")
def inspect_apk(path: str):
    p = resolve_file(path)
    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile as exc:
        raise ReaError(f"Not a valid ZIP/APK: {exc}")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ReaError("Archive has too many entries")
        names = [i.filename for i in infos]
        if "AndroidManifest.xml" not in names:
            raise ReaError("No AndroidManifest.xml: not an APK")
        mi = zf.getinfo("AndroidManifest.xml")
        if mi.file_size > MAX_MANIFEST:
            raise ReaError("Manifest too large")
        manifest = parse_manifest(zf.read(mi))
        dex = []
        for n in sorted(x for x in names if x.startswith("classes") and x.endswith(".dex")):
            with zf.open(n) as f:
                h = f.read(112)
            if h[:4] == b"dex\n" and len(h) >= 112:
                dex.append({"file": n, "version": h[4:7].decode("ascii", "replace"),
                            "method_ids": struct.unpack_from("<I", h, 0x58)[0], "class_defs": struct.unpack_from("<I", h, 0x60)[0]})
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
        libs = sorted({n.split("/")[-1] for n in names if n.startswith("lib/") and n.endswith(".so")})
        sig_files = [n for n in names if n.startswith("META-INF/") and n.rsplit(".", 1)[-1].upper() in ("RSA", "DSA", "EC", "SF", "MF")]
        markers = {
            "flutter": any(l in libs for l in ("libflutter.so", "libapp.so")) or any(n.startswith("assets/flutter_assets/") for n in names),
            "react_native": "libreactnativejni.so" in libs or "assets/index.android.bundle" in names,
            "unity": "libunity.so" in libs,
            "il2cpp": "libil2cpp.so" in libs,
            "xamarin_or_maui": any(n.startswith("assemblies/") for n in names) or "libmonodroid.so" in libs,
            "kotlin_multiplatform_or_kotlin": any(n.startswith("kotlin/") for n in names),
        }
        findings = {
            "size_bytes": p.stat().st_size, "entry_count": len(names), "manifest": {**manifest, "permission_count": len(manifest["permissions"])},
            "dex": dex, "native_abis": abis, "native_libraries": libs[:200], "signing_files": sig_files,
            "v1_signature_files_present": any(n.endswith((".RSA", ".DSA", ".EC")) for n in sig_files),
            "framework_markers": {k: v for k, v in markers.items() if v}, "has_resources_arsc": "resources.arsc" in names,
        }
    return result(
        "inspect_apk", path, findings,
        [{"kind": "zip-directory+axml", "detail": "Read the ZIP central directory, decoded AndroidManifest.xml binary XML and DEX headers."}],
        [
            "No decompilation: class and method bodies are not recovered (use JADX for that).",
            "Only v1 (JAR) signature files are detected; v2/v3 signing blocks are not parsed or verified.",
            "Manifest values that reference resources (e.g. @string/app_name) appear as raw numbers.",
        ],
    )
