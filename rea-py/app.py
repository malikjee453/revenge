"""Streamlit web UI for rea-py. Upload a file, pick an analyzer, read findings/evidence/limitations.

Run locally:   streamlit run app.py
Deploy:        Streamlit Community Cloud -> main file path: app.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from rea_py import analyzers  # noqa: E402,F401  (registers the tools)
from rea_py.registry import TOOLS, call_tool  # noqa: E402
from rea_py.util import ReaError  # noqa: E402

st.set_page_config(page_title="rea-py", page_icon="🔍", layout="wide")

FORMAT_TO_TOOL = {
    "elf": "inspect_elf", "pe": "inspect_pe", "macho": "inspect_macho", "macho-fat": "inspect_macho",
    "sqlite": "inspect_sqlite", "gguf": "inspect_model_file", "safetensors": "inspect_model_file",
    "har": "inspect_har", "asar": "analyze_javascript_application", "zip": "inspect_apk",
}
DEFAULTS = {"min_length": 6, "max_results": 500, "max_entries": 100, "sample_rows": 5}
# Directory analysis only makes sense on a local machine, so the hosted UI sticks to single files.
TOOL_NAMES = [n for n in TOOLS if n != "detect_file_type"]


def stage(upload) -> str:
    """Write the upload to a temp file once per upload; targets are only read, never executed."""
    key = f"{upload.name}:{upload.size}"
    if st.session_state.get("staged_key") != key:
        old = st.session_state.get("staged_path")
        if old and os.path.exists(old):
            os.unlink(old)
        fd, path = tempfile.mkstemp(suffix=Path(upload.name).suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(upload.getbuffer())
        st.session_state.update(staged_key=key, staged_path=path)
    return st.session_state["staged_path"]


st.title("🔍 rea-py")
st.caption("Static analysis of binaries, apps, model files and captures. Files are only read, never executed. "
           "Inspired by [REA](https://github.com/morluto/rea) (MIT).")

upload = st.file_uploader("Upload a file to analyze")
if upload is None:
    st.info("Supported: ELF, PE, Mach-O, APK, Electron .asar, SQLite, GGUF, safetensors, HAR, Go binaries, or any file for strings.")
    st.stop()

path = stage(upload)
detected = call_tool("detect_file_type", {"path": path})["findings"]["format"]
st.write(f"Detected format: **{detected}** · {upload.size:,} bytes")

suggested = FORMAT_TO_TOOL.get(detected, "extract_strings")
tool_name = st.selectbox("Analyzer", TOOL_NAMES, index=TOOL_NAMES.index(suggested), format_func=lambda n: n.replace("_", " "))
st.caption(TOOLS[tool_name].description)

args = {"path": path}
for key, spec in TOOLS[tool_name].schema["properties"].items():
    if key == "path":
        continue
    label = f"{key} — {spec.get('description', '')}"
    kind = spec.get("type")
    if kind == "boolean":
        if st.checkbox(label, key=f"{tool_name}.{key}"):
            args[key] = True
    elif kind == "integer":
        args[key] = int(st.number_input(label, min_value=1, value=DEFAULTS.get(key, 10), key=f"{tool_name}.{key}"))
    else:
        text = st.text_input(label, key=f"{tool_name}.{key}")
        if text:
            args[key] = text

if st.button("Analyze", type="primary"):
    try:
        with st.spinner("Analyzing…"):
            out = call_tool(tool_name, args)
    except ReaError as exc:
        st.error(str(exc))
        st.stop()
    out["target"] = upload.name
    st.subheader("Findings")
    st.json(out["findings"], expanded=2)
    st.subheader("Limitations")
    for item in out["limitations"]:
        st.warning(item)
    with st.expander(f"Evidence ({len(out['evidence'])})"):
        st.json(out["evidence"])
    st.download_button("Download JSON report", json.dumps(out, indent=2, default=str),
                       file_name=f"{Path(upload.name).stem}-{tool_name}.json", mime="application/json")
