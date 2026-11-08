"""Java archive (JAR/WAR) inspection."""
from __future__ import annotations

import zipfile
from collections import Counter
from typing import Any, Dict, List

from ..registry import tool
from ..util import ReaError, resolve_file, result


def _manifest(text: str) -> Dict[str, str]:
    lines: List[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    out: Dict[str, str] = {}
    for ln in lines:
        if not ln.strip():
            break  # main section ends at the first blank line
        if ":" in ln:
            k, v = ln.split(":", 1)
            out[k.strip()] = v.strip()
    return out


@tool("inspect_jar", "Inspect a JAR/WAR: manifest (Main-Class, versions), class file Java versions, top packages, nested jars, signing and Spring Boot layout.")
def inspect_jar(path: str):
    p = resolve_file(path)
    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile as exc:
        raise ReaError(f"Not a valid ZIP/JAR: {exc}")
    with zf:
        names = zf.namelist()
        classes = [n for n in names if n.endswith(".class")]
        manifest: Dict[str, str] = {}
        if "META-INF/MANIFEST.MF" in names:
            mi = zf.getinfo("META-INF/MANIFEST.MF")
            if mi.file_size <= 1024 * 1024:
                manifest = _manifest(zf.read(mi).decode("utf-8", "replace"))
        majors: Counter = Counter()
        for n in classes[:100]:
            with zf.open(n) as f:
                h = f.read(8)
            if h[:4] == b"\xca\xfe\xba\xbe":
                majors[int.from_bytes(h[6:8], "big")] += 1
        pk: Counter = Counter("/".join(n.split("/")[:-1][:3]) for n in classes if "/" in n)
        findings = {
            "entry_count": len(names), "class_count": len(classes), "manifest": manifest,
            "main_class": manifest.get("Main-Class") or manifest.get("Start-Class"),
            "class_file_majors": {str(k): v for k, v in majors.items()},
            "java_release_guess": (max(majors) - 44 if max(majors) >= 49 else f"1.{max(majors) - 44}") if majors else None,
            "top_packages": dict(pk.most_common(20)),
            "nested_jars": [n for n in names if n.endswith(".jar")][:100],
            "signed": any(n.startswith("META-INF/") and n.endswith(".SF") for n in names),
            "spring_boot_layout": any(n.startswith("BOOT-INF/") for n in names),
            "service_files": [n for n in names if n.startswith("META-INF/services/") and not n.endswith("/")][:50],
            "multi_release": manifest.get("Multi-Release", "").lower() == "true",
        }
    return result(
        "inspect_jar", path, findings,
        [{"kind": "zip-directory+manifest", "detail": "Read the ZIP directory, manifest and up to 100 class headers."}],
        ["No decompilation: bytecode is not decoded (use CFR, Procyon or JADX).",
         "Java version is guessed from the first 100 class files; multi-release jars can mix versions.",
         "Signature files are detected but not verified."],
    )
