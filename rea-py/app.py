"""BinXray: Streamlit web UI. Upload a file, get a full static-analysis report.

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

from binxray import analyzers  # noqa: E402,F401  (registers the tools)
from binxray.registry import TOOLS, call_tool  # noqa: E402
from binxray.util import ReaError  # noqa: E402

st.set_page_config(page_title="BinXray", page_icon="🩻", layout="wide")

DEFAULTS = {"min_length": 6, "max_results": 500, "max_entries": 100, "sample_rows": 5, "block_size": 65536}
# Directory analysis only makes sense on a local machine, so the hosted UI sticks to single files.
TOOL_NAMES = ["full_report"] + [n for n in TOOLS if n not in ("full_report", "detect_file_type")]


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


def show(out: dict, title: str):
    st.subheader(title)
    st.json(out["findings"], expanded=1)
    for item in out["limitations"]:
        st.warning(item)
    if out["evidence"]:
        with st.expander(f"Evidence ({len(out['evidence'])})"):
            st.json(out["evidence"])


st.title("🩻 BinXray")
st.caption("Static analysis for binaries, apps, model files and captures. Files are only read, never executed. "
           "Authorized use only: analyze software you own or have permission to examine.")

upload = st.file_uploader("Upload a file to analyze")
if upload is None:
    st.info("Formats: ELF, PE, Mach-O, APK, JAR, Electron .asar, WASM, SQLite, GGUF, safetensors, HAR, Go binaries. "
            "Any file also gets hashes, entropy, embedded-file and indicator scans.")
    st.stop()

path = stage(upload)
detected = call_tool("detect_file_type", {"path": path})["findings"]["format"]
st.write(f"Detected format: **{detected}** · {upload.size:,} bytes")

tool_name = st.selectbox("Analyzer", TOOL_NAMES, format_func=lambda n: n.replace("_", " "))
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
    if tool_name == "full_report":
        st.success(f"Ran: {', '.join(out['findings']['analyzers_run'])}")
        for name, section in out["findings"]["sections"].items():
            if "error" in section:
                st.error(f"{name}: {section['error']}")
            else:
                section["target"] = upload.name
                with st.expander(name.replace("_", " "), expanded=name.startswith("inspect_") and name == out["findings"]["analyzers_run"][0]):
                    show(section, name.replace("_", " "))
        for item in out["limitations"]:
            st.info(item)
    else:
        show(out, "Findings")
    st.download_button("Download JSON report", json.dumps(out, indent=2, default=str),
                       file_name=f"{Path(upload.name).stem}-{tool_name}.json", mime="application/json")
