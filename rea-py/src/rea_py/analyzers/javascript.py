"""Static JavaScript / Electron application analysis for directories and ASAR archives."""
from __future__ import annotations

import json
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Tuple

from ..registry import tool
from ..util import ReaError, resolve_any, result

MAX_FILES = 20000
MAX_SCANNED = 3000
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE = 300
JS_EXT = (".js", ".mjs", ".cjs")
NODE_BUILTINS = {
    "fs", "path", "os", "child_process", "net", "http", "https", "crypto", "zlib", "stream", "events", "url",
    "util", "assert", "buffer", "cluster", "dgram", "dns", "tls", "readline", "vm", "worker_threads", "module",
}
RX_REQUIRE = re.compile(r"""require\(\s*['"]([^'"\n]+)['"]\s*\)""")
RX_IMPORT = re.compile(r"""(?:\bfrom|\bimport)\s*\(?\s*['"]([^'"\n]+)['"]""")
RX_IPC = re.compile(r"""(ipcMain|ipcRenderer)\s*\.\s*(handle|handleOnce|on|once|invoke|send|sendSync)\s*\(\s*['"`]([^'"`\n]+)['"`]""")
RX_EXPOSE = re.compile(r"""exposeInMainWorld\s*\(\s*['"]([^'"\n]+)['"]""")
RX_SOURCEMAP = re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)""")
RX_RISKY = [
    ("nodeIntegration enabled", re.compile(r"nodeIntegration\s*:\s*(?:true|!0)")),
    ("contextIsolation disabled", re.compile(r"contextIsolation\s*:\s*(?:false|!1)")),
    ("webSecurity disabled", re.compile(r"webSecurity\s*:\s*(?:false|!1)")),
    ("sandbox disabled", re.compile(r"sandbox\s*:\s*(?:false|!1)")),
]
Reader = Callable[[], bytes]


def _iter_dir(root: Path) -> Iterator[Tuple[str, int, Reader]]:
    for f in root.rglob("*"):
        if f.is_file() and not f.is_symlink():
            yield f.relative_to(root).as_posix(), f.stat().st_size, (lambda f=f: f.read_bytes())


def _iter_asar(path: Path) -> Iterator[Tuple[str, int, Reader]]:
    with open(path, "rb") as fh:
        head = fh.read(16)
        if len(head) < 16 or struct.unpack_from("<I", head, 0)[0] != 4:
            raise ReaError("Not an ASAR archive")
        header_size = struct.unpack_from("<I", head, 4)[0]
        json_len = struct.unpack_from("<I", head, 12)[0]
        if json_len > 64 * 1024 * 1024:
            raise ReaError("ASAR header too large")
        tree = json.loads(fh.read(json_len).decode("utf-8"))
    base = 8 + header_size

    def walk(node: Dict[str, Any], prefix: str):
        for name, child in node.get("files", {}).items():
            rel = f"{prefix}{name}"
            if "files" in child:
                yield from walk(child, rel + "/")
            else:
                size = int(child.get("size", 0))
                if child.get("unpacked") or "offset" not in child:
                    yield rel, size, (lambda: b"")
                    continue
                off = base + int(child["offset"])

                def read(off=off, size=size) -> bytes:
                    with open(path, "rb") as f:
                        f.seek(off)
                        return f.read(size)

                yield rel, size, read

    yield from walk(tree, "")


@tool(
    "analyze_javascript_application",
    "Statically analyze an extracted JavaScript/Electron app directory or an .asar archive: package metadata, imports, Electron IPC and preload bridges, risky window settings, native add-ons and source maps.",
    path_description="Absolute path to an app directory or .asar file.",
)
def analyze_javascript_application(path: str):
    p = resolve_any(path)
    if p.is_dir():
        source, kind = _iter_dir(p), "directory"
    else:
        source, kind = _iter_asar(p), "asar"

    files: List[Tuple[str, int, Reader]] = []
    for item in source:
        files.append(item)
        if len(files) >= MAX_FILES:
            break
    truncated_files = len(files) >= MAX_FILES

    ext_count = Counter(Path(r).suffix.lower() or "(none)" for r, _s, _f in files)
    native_addons = [r for r, _s, _f in files if r.endswith(".node")]

    pkgs = sorted((r for r, _s, _f in files if r.endswith("package.json") and "node_modules/" not in r), key=lambda r: r.count("/"))
    package: Dict[str, Any] = {}
    if pkgs:
        reader = next(f for r, _s, f in files if r == pkgs[0])
        try:
            raw = json.loads(reader().decode("utf-8-sig"))
            deps = {**raw.get("dependencies", {}), **raw.get("devDependencies", {})}
            package = {
                "file": pkgs[0], "name": raw.get("name"), "version": raw.get("version"), "main": raw.get("main"),
                "dependency_count": len(raw.get("dependencies", {})),
                "dev_dependency_count": len(raw.get("devDependencies", {})),
                "electron_version_declared": deps.get("electron"),
                "top_dependencies": sorted(raw.get("dependencies", {}))[:50],
            }
        except (ValueError, UnicodeError):
            package = {"file": pkgs[0], "error": "package.json could not be parsed"}

    ext_imports: Counter = Counter()
    builtins: Counter = Counter()
    relative = 0
    ipc: List[Dict[str, Any]] = []
    bridges: List[str] = []
    maps: List[str] = []
    risky: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    scanned = 0

    def note(file: str, text: str, kind_: str, offset: int):
        if len(evidence) < MAX_EVIDENCE:
            evidence.append({"kind": kind_, "file": file, "line": text.count("\n", 0, offset) + 1, "match": text[offset : offset + 100].split("\n")[0]})

    for rel, size, reader in files:
        if not rel.lower().endswith(JS_EXT) or "node_modules/" in rel or size > MAX_SCAN_BYTES:
            continue
        if scanned >= MAX_SCANNED:
            break
        scanned += 1
        text = reader().decode("utf-8", errors="replace")
        for rx in (RX_REQUIRE, RX_IMPORT):
            for mt in rx.finditer(text):
                spec = mt.group(1)
                if spec.startswith((".", "/")):
                    relative += 1
                else:
                    name = spec[5:] if spec.startswith("node:") else spec
                    root = "/".join(name.split("/")[:2]) if name.startswith("@") else name.split("/")[0]
                    (builtins if root in NODE_BUILTINS else ext_imports)[root] += 1
        for mt in RX_IPC.finditer(text):
            ipc.append({"side": mt.group(1), "method": mt.group(2), "channel": mt.group(3), "file": rel})
            note(rel, text, "ipc", mt.start())
        for mt in RX_EXPOSE.finditer(text):
            bridges.append(mt.group(1))
            note(rel, text, "preload-bridge", mt.start())
        for mt in RX_SOURCEMAP.finditer(text):
            maps.append(mt.group(1)[:200] if not mt.group(1).startswith("data:") else "data: URI (inline source map)")
        for label, rx in RX_RISKY:
            for mt in rx.finditer(text):
                risky.append({"setting": label, "file": rel})
                note(rel, text, "risky-setting", mt.start())

    electron = bool(package.get("electron_version_declared")) or "electron" in ext_imports or bool(bridges) or any(i["side"].startswith("ipc") for i in ipc)
    ipc_channels = sorted({(i["side"], i["channel"]) for i in ipc})
    findings = {
        "container": kind, "file_count": len(files), "files_truncated": truncated_files, "extensions": dict(ext_count.most_common(15)),
        "package": package, "electron_detected": electron, "scripts_scanned": scanned,
        "external_imports": dict(ext_imports.most_common(60)), "node_builtin_imports": dict(builtins.most_common()),
        "relative_import_count": relative,
        "ipc": {"channel_count": len(ipc_channels), "channels": [{"side": s, "channel": c} for s, c in ipc_channels[:200]]},
        "preload_bridges": sorted(set(bridges)), "risky_window_settings": risky[:50],
        "native_addons": native_addons[:100], "source_maps": sorted(set(maps))[:50],
    }
    return result(
        "analyze_javascript_application", path, findings, evidence,
        [
            "Regex-based scan: it does not build an AST, so dynamic require() calls, string concatenation and minified code can be missed or misclassified.",
            f"Scans at most {MAX_SCANNED} scripts under {MAX_SCAN_BYTES // 1024 // 1024} MiB each; node_modules contents are inventoried but not scanned.",
            "Nothing is executed. Risky-setting matches show the pattern exists, not that the code path is reachable.",
            "Files marked 'unpacked' in an ASAR live outside the archive and are not read.",
        ],
    )
