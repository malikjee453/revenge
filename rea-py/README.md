# 🩻 BinXray

Static analysis for compiled software, apps, model files and network captures. BinXray ships a
**Streamlit web UI**, a **CLI**, and an **MCP server** (so AI agents can use it). Every result contains
`findings`, `evidence` and `limitations`. Pure standard library; the UI needs only `streamlit`.

> Use only on software you own or are authorized to examine. BinXray reads files; it never executes them.
> See `NOTICE.md` for attribution.

## Analyzers (18)

| Tool | Target | Returns |
|---|---|---|
| `full_report` | any file | Detects the format and runs every applicable analyzer below in one call |
| `detect_file_type` | any file | Format from magic bytes (ELF, PE, Mach-O, APK, JAR, ASAR, WASM, SQLite, GGUF, safetensors, HAR...) |
| `fingerprint_file` | any file | MD5/SHA-1/SHA-256, entropy map, packer markers (UPX, PyInstaller, VMProtect, Themida...) |
| `find_embedded_files` | any file | Embedded zip/gzip/png/elf/pe/sqlite/pdf/pem offsets (binwalk-style) |
| `extract_indicators` | any file | URLs, IPs, emails, paths, registry keys, masked secret candidates, crypto constants |
| `extract_strings` | any file | ASCII / UTF-16LE strings with offsets |
| `inspect_elf` | ELF | Header, segments, sections, needed libs, build-id, PIE/NX/RELRO |
| `inspect_elf_symbols` | ELF | Imported/exported symbols from `.dynsym` / `.symtab` |
| `inspect_pe` | PE | Headers, sections, imports, **exports**, ASLR/DEP/CFG, .NET and signature flags |
| `inspect_macho` | Mach-O | CPU, UUID, segments, dylibs, rpaths, PIE, code-signature presence |
| `inspect_go_buildinfo` | Go (1.18+) | Compiler version, module, dependencies, build flags |
| `inspect_apk` | APK | Manifest, permissions, components, DEX, ABIs, framework markers |
| `inspect_jar` | JAR/WAR | Manifest, Main-Class, Java version, packages, nested jars, signing |
| `analyze_javascript_application` | Electron dir / `.asar` | Imports, IPC, preload bridges, risky window settings, native add-ons |
| `inspect_wasm` | WebAssembly | Sections, imports, exports, custom sections |
| `inspect_model_file` | GGUF / safetensors | Metadata, tensor shapes, parameter totals |
| `inspect_sqlite` | SQLite | Schema, optional row counts and samples (read-only) |
| `inspect_har` | HAR | Hosts, methods, statuses, API-like requests (no header/body values) |

## What BinXray does not do

It is not a decompiler or disassembler, does not run or debug programs, and does not unpack
protected binaries or bypass licensing or protections. For deeper work pair it with Ghidra, Rizin,
JADX, CFR or wasm2wat. Each result's `limitations` list states what that specific analysis cannot tell you.

## Web UI

```bash
pip install -r requirements.txt
streamlit run app.py
```

Streamlit Community Cloud: set the main file path to `app.py`.

## CLI

```bash
python -m binxray full-report C:\path\to\app.exe
python -m binxray inspect-pe app.exe --compact
python -m binxray extract-indicators firmware.bin
python -m binxray list-tools
```

`pip install .` also provides a `binxray` command. Exit status: `0` success, `2` user-facing error.

## MCP server

```bash
python -m binxray serve
```

```json
{ "mcpServers": { "binxray": { "command": "python", "args": ["-m", "binxray", "serve"] } } }
```

Run it with the project's `src` folder on `PYTHONPATH` (or after `pip install .`).

## Safety model

* Targets are memory-mapped **read-only** and never executed.
* SQLite opens with `mode=ro` and `PRAGMA query_only=ON`; HAR output never includes header/cookie/body values.
* Secret candidates are masked in output.
* Parsers cap counts and sizes; malformed input returns an error result, not a crash.

## Development

```bash
python -m unittest discover -s tests
```

MIT licensed. See `LICENSE` and `NOTICE.md`.
