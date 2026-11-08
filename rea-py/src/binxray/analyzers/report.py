"""One-call full report: detect the format, then run every applicable analyzer."""
from __future__ import annotations

from typing import Any, Dict

from ..registry import call_tool, tool
from ..util import ReaError, result

NATIVE = ["inspect_go_buildinfo"]
FORMAT_TOOLS = {
    "elf": ["inspect_elf", "inspect_elf_symbols"] + NATIVE, "pe": ["inspect_pe"] + NATIVE,
    "macho": ["inspect_macho"] + NATIVE, "macho-fat": ["inspect_macho"] + NATIVE,
    "sqlite": ["inspect_sqlite"], "gguf": ["inspect_model_file"], "safetensors": ["inspect_model_file"],
    "har": ["inspect_har"], "asar": ["analyze_javascript_application"], "apk": ["inspect_apk"],
    "jar": ["inspect_jar"], "wasm": ["inspect_wasm"],
}
ALWAYS = ["fingerprint_file", "find_embedded_files", "extract_indicators"]


@tool("full_report", "Run everything that applies to a file in one call: format detection, the matching structural analyzers, hashes/entropy, embedded files and indicators.")
def full_report(path: str):
    fmt = call_tool("detect_file_type", {"path": path})["findings"]["format"]
    sections: Dict[str, Any] = {}
    for name in FORMAT_TOOLS.get(fmt, []) + ALWAYS:
        try:
            sections[name] = call_tool(name, {"path": path})
        except ReaError as exc:
            sections[name] = {"error": str(exc)}
    return result(
        "full_report", path, {"format": fmt, "analyzers_run": list(sections), "sections": sections}, [],
        ["Each section carries its own evidence and limitations; read them before drawing conclusions.",
         "Unknown formats still get fingerprint, embedded-file and indicator scans, but no structural analysis."],
    )
