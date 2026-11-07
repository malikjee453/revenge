# rea-py

A Python, dependency-free reimplementation of the **static-analysis core** of
[REA — Reverse Engineer Anything](https://github.com/morluto/rea). It exposes the same style of
workflow as the original: an **MCP server** (so an AI agent can inspect a target) and a **CLI**, and
every result contains `findings`, `evidence` and `limitations`.

> Read `NOTICE.md` for attribution. Use this only on software you own or are authorized to examine.

## What's implemented

| Tool (CLI name) | Target | Returns |
|---|---|---|
| `detect-file-type` | any file | Format from magic bytes |
| `inspect-elf` | ELF | Header, segments, sections, needed libs, build-id, PIE/NX/RELRO |
| `inspect-pe` | PE (EXE/DLL) | Headers, sections, imports, ASLR/DEP/CFG flags, .NET and signature indicators |
| `inspect-macho` | Mach-O (thin/fat) | CPU, UUID, segments, dylibs, rpaths, PIE, code-signature presence |
| `inspect-go-buildinfo` | Go binaries (1.18+) | Compiler version, module, dependencies, build flags |
| `inspect-model-file` | GGUF / safetensors | Metadata, tensor shapes, parameter totals |
| `inspect-sqlite` | SQLite | Schema, optional row counts and sample rows (read-only) |
| `inspect-har` | HAR captures | Hosts, methods, statuses, API-like requests (no header/body values) |
| `analyze-javascript-application` | JS/Electron dir or `.asar` | package.json, imports, IPC channels, preload bridges, risky window settings, native add-ons, source maps |
| `inspect-apk` | Android APK | Manifest (binary XML), DEX headers, ABIs, signing files, Flutter/RN/Unity markers |
| `extract-strings` | any file | ASCII / UTF-16LE strings with offsets |

## Not ported (needs external engines or large amounts of work)

Hopper / Ghidra / IDA / Kuna bridges and decompilation, JADX, JEB, Apktool, browser observation,
ADB device analysis, firmware extraction, packet/pcap/logic-signal analysis, process capture,
RL-environment export, EVM/WASM/BEAM/IL2CPP/Godot/PyInstaller analyzers, PE certificate parsing,
and the agent setup installer. See the upstream project for those.

## Run without installing

```bash
python app.py list-tools
python app.py inspect-elf /usr/bin/ls --compact
python app.py serve
```

## Install

Requires Python 3.9+. No third-party packages.

```bash
pip install .
rea-py list-tools
```

## CLI

```bash
rea-py inspect-pe C:\path\to\app.exe
rea-py inspect-elf /usr/bin/ls --compact
rea-py analyze-javascript-application /path/to/app.asar
rea-py extract-strings firmware.bin --min-length 8 --contains http
rea-py inspect-sqlite data.db --include-row-counts --sample-table notes --sample-rows 5
```

Exit status is `0` on success and `2` on a user-facing error (bad path, malformed file).

## MCP server

```bash
rea-py serve        # or: python app.py serve
```

Example client registration (Claude Desktop / Claude Code style JSON):

```json
{
  "mcpServers": {
    "rea-py": { "command": "python", "args": ["C:/full/path/to/rea-py/app.py", "serve"] }
  }
}
```

Transport is newline-delimited JSON-RPC over stdio. Supported methods: `initialize`, `ping`,
`tools/list`, `tools/call`.

## Safety model

* Targets are memory-mapped **read-only** and never executed.
* SQLite is opened with `mode=ro` and `PRAGMA query_only=ON`.
* HAR output never includes header, cookie, or body values.
* Parsers cap counts and sizes; malformed input yields an error result, not a crash.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT. See `LICENSE` and `NOTICE.md`.
