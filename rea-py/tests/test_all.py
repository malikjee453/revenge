import io
import json
import os
import sqlite3
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from binxray import analyzers  # noqa: E402,F401
from binxray.mcp_server import handle, serve  # noqa: E402
from binxray.registry import call_tool  # noqa: E402
from binxray.util import ReaError  # noqa: E402


def uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_pe():
    b = bytearray(0x800)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x40)
    b[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", b, 0x44, 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = 0x58
    struct.pack_into("<H", b, opt, 0x20B)
    struct.pack_into("<I", b, opt + 16, 0x1000)
    struct.pack_into("<Q", b, opt + 24, 0x140000000)
    struct.pack_into("<HH", b, opt + 68, 3, 0x40 | 0x100 | 0x4000)
    struct.pack_into("<I", b, opt + 108, 16)
    struct.pack_into("<II", b, opt + 112 + 8, 0x1000, 40)  # import dir
    struct.pack_into("<II", b, opt + 112, 0x1400, 0x60)  # export dir
    sec = opt + 240
    struct.pack_into("<8sIIIIIIHHI", b, sec, b".text", 0x600, 0x1000, 0x600, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<IIIII", b, 0x200, 0x1100, 0, 0, 0x1200, 0x1100)
    struct.pack_into("<Q", b, 0x300, 0x1300)
    b[0x400:0x400 + 13] = b"KERNEL32.dll\0"
    b[0x500:0x500 + 14] = b"\0\0ExitProcess\0"
    struct.pack_into("<IIHHIIIIIII", b, 0x600, 0, 0, 0, 0, 0x1480, 1, 1, 1, 0x1440, 0x1450, 0x1458)
    struct.pack_into("<I", b, 0x640, 0x1000)
    struct.pack_into("<I", b, 0x650, 0x1490)
    struct.pack_into("<H", b, 0x658, 0)
    b[0x680:0x68A] = b"mylib.dll\0"
    b[0x690:0x699] = b"MyExport\0"
    return bytes(b)


def build_macho():
    uuid = bytes(range(16))
    name = b"/usr/lib/libSystem.B.dylib\0"
    dl_size = (24 + len(name) + 7) & ~7
    cmds = struct.pack("<II", 0x1B, 24) + uuid
    cmds += struct.pack("<IIIIII", 0xC, dl_size, 24, 0, 0, 0) + name + b"\0" * (dl_size - 24 - len(name))
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(cmds), 0x200000, 0)
    return hdr + cmds


def build_axml():
    strings = ["manifest", "package", "com.example.app", "versionName", "1.2.3", "uses-permission", "name", "android.permission.INTERNET"]
    enc = [struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\0\0" for s in strings]
    offs, pos = [], 0
    for e in enc:
        offs.append(pos)
        pos += len(e)
    blob = b"".join(enc)
    blob += b"\0" * (-len(blob) % 4)
    hsize = 28
    sp = struct.pack("<HHIIIIII", 1, hsize, hsize + 4 * len(strings) + len(blob), len(strings), 0, 0, hsize + 4 * len(strings), 0)
    sp += struct.pack(f"<{len(strings)}I", *offs) + blob

    def start(name_i, attrs):
        body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_i, 20, 20, len(attrs), 0, 0, 0)
        for an, val_i in attrs:
            body += struct.pack("<IIIHBBI", 0xFFFFFFFF, an, val_i, 8, 0, 0x03, val_i)
        return struct.pack("<HHIII", 0x102, 16, 16 + len(body), 1, 0xFFFFFFFF) + body

    def end(name_i):
        return struct.pack("<HHIII", 0x103, 16, 24, 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, name_i)

    body = sp + start(0, [(1, 2), (3, 4)]) + start(5, [(6, 7)]) + end(5) + end(0)
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data) if isinstance(data, bytes) else p.write_text(data)
        return str(p)


class TestBinaries(Base):
    @unittest.skipUnless(sys.platform.startswith("linux") and os.path.exists("/bin/ls"), "needs Linux ELF")
    def test_elf_real_binary(self):
        r = call_tool("inspect_elf", {"path": os.path.realpath("/bin/ls")})
        f = r["findings"]
        self.assertEqual(f["class"], 64)
        self.assertTrue(any("libc" in n for n in f["needed_libraries"]))
        self.assertIn("pie", f["hardening"])

    def test_pe(self):
        r = call_tool("inspect_pe", {"path": self.write("a.exe", build_pe())})["findings"]
        self.assertEqual(r["architecture"], "x64")
        self.assertEqual(r["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(r["imports"][0]["functions"], ["ExitProcess"])
        self.assertEqual(r["export_name"], "mylib.dll")
        self.assertEqual(r["exports"][0]["name"], "MyExport")
        self.assertEqual(r["exports"][0]["ordinal"], 1)
        self.assertTrue(r["hardening"]["aslr_dynamic_base"] and r["hardening"]["control_flow_guard"])

    def test_macho(self):
        r = call_tool("inspect_macho", {"path": self.write("a.macho", build_macho())})["findings"]["slices"][0]
        self.assertEqual(r["cpu"], "arm64")
        self.assertTrue(r["hardening"]["pie"])
        self.assertEqual(r["dylibs"][0]["name"], "/usr/lib/libSystem.B.dylib")
        self.assertEqual(r["uuid"], "00010203-0405-0607-0809-0a0b0c0d0e0f")

    def test_go_buildinfo(self):
        mod = b"\x00" * 16 + b"path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgithub.com/x/y\tv1.0.0\th1:abc\nbuild\tCGO_ENABLED=0\n" + b"\x00" * 16
        ver = b"go1.22.1"
        blob = b"\xff Go buildinf:" + bytes([8, 2]) + b"\0" * 16 + uvarint(len(ver)) + ver + uvarint(len(mod)) + mod
        r = call_tool("inspect_go_buildinfo", {"path": self.write("go.bin", b"\0" * 32 + blob)})["findings"]
        self.assertEqual(r["go_version"], "go1.22.1")
        self.assertEqual(r["dependencies"][0]["path"], "github.com/x/y")
        self.assertEqual(r["build_settings"]["CGO_ENABLED"], "0")

    def test_strings(self):
        p = self.write("s.bin", b"\0\0hello_world_string\0\0x\0another one here\0")
        r = call_tool("extract_strings", {"path": p, "contains": "another"})["findings"]
        self.assertEqual([s["text"] for s in r["strings"]], ["another one here"])

    def test_malformed_raises_rea_error(self):
        with self.assertRaises(ReaError):
            call_tool("inspect_pe", {"path": self.write("bad.exe", b"MZ" + b"\0" * 10)})

    def test_detect(self):
        self.assertEqual(call_tool("detect_file_type", {"path": self.write("a.exe", build_pe())})["findings"]["format"], "pe")


class TestData(Base):
    def test_safetensors(self):
        hdr = json.dumps({"__metadata__": {"format": "pt"}, "w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]}}).encode()
        p = self.write("m.safetensors", struct.pack("<Q", len(hdr)) + hdr + b"\0" * 24)
        r = call_tool("inspect_model_file", {"path": p})["findings"]
        self.assertEqual(r["total_parameters"], 6)
        self.assertEqual(r["offset_problems"], [])
        self.assertEqual(call_tool("detect_file_type", {"path": p})["findings"]["format"], "safetensors")

    def test_gguf(self):
        def s(x):
            b = x.encode()
            return struct.pack("<Q", len(b)) + b
        data = b"GGUF" + struct.pack("<IQQ", 3, 1, 1) + s("general.architecture") + struct.pack("<I", 8) + s("llama")
        data += s("blk.0.w") + struct.pack("<I", 2) + struct.pack("<QQ", 4, 8) + struct.pack("<IQ", 1, 0)
        r = call_tool("inspect_model_file", {"path": self.write("m.gguf", data)})["findings"]
        self.assertEqual(r["architecture"], "llama")
        self.assertEqual(r["total_parameters"], 32)
        self.assertEqual(r["tensors"][0]["type"], "F16")

    def test_sqlite(self):
        p = self.dir / "t.db"
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, raw BLOB)")
        con.execute("INSERT INTO notes (body, raw) VALUES ('hi', x'0102')")
        con.commit()
        con.close()
        r = call_tool("inspect_sqlite", {"path": str(p), "include_row_counts": True, "sample_table": "notes"})["findings"]
        self.assertEqual(r["tables"][0]["row_count"], 1)
        self.assertEqual(r["sample"]["rows"][0]["raw"]["blob_bytes"], 2)
        with self.assertRaises(ReaError):
            call_tool("inspect_sqlite", {"path": str(p), "sample_table": "nope"})

    def test_har_hides_secrets(self):
        har = {"log": {"creator": {"name": "t"}, "entries": [{
            "request": {"method": "GET", "url": "https://a.test/api/items?token=SECRET", "headers": [{"name": "Authorization", "value": "Bearer SECRET"}]},
            "response": {"status": 200, "content": {"mimeType": "application/json", "size": 5}}, "time": 3}]}}
        out = call_tool("inspect_har", {"path": self.write("c.har", json.dumps(har))})
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(out["findings"]["requests_with_credential_headers"], 1)
        self.assertEqual(out["findings"]["api_like_requests"], 1)


class TestApps(Base):
    def test_js_directory(self):
        self.write("app/package.json", json.dumps({"name": "demo", "main": "main.js", "dependencies": {"left-pad": "1"}, "devDependencies": {"electron": "30.0.0"}}))
        self.write("app/main.js", "const {ipcMain,BrowserWindow}=require('electron');const fs=require('fs');\nipcMain.handle('notes:save',()=>{});\nnew BrowserWindow({webPreferences:{nodeIntegration:true}});\n")
        self.write("app/preload.js", "contextBridge.exposeInMainWorld('api',{});\n")
        r = call_tool("analyze_javascript_application", {"path": str(self.dir / "app")})["findings"]
        self.assertTrue(r["electron_detected"])
        self.assertEqual(r["ipc"]["channels"][0]["channel"], "notes:save")
        self.assertEqual(r["preload_bridges"], ["api"])
        self.assertEqual(r["risky_window_settings"][0]["setting"], "nodeIntegration enabled")
        self.assertIn("fs", r["node_builtin_imports"])

    def test_asar(self):
        js = b"require('electron');ipcRenderer.send('ping');"
        pkg = b'{"name":"x"}'
        tree = {"files": {"main.js": {"size": len(js), "offset": "0"}, "package.json": {"size": len(pkg), "offset": str(len(js))}}}
        j = json.dumps(tree).encode()
        pad = (-len(j)) % 4
        pickle_payload = 4 + len(j) + pad
        header = struct.pack("<IIII", 4, pickle_payload + 4, pickle_payload, len(j)) + j + b"\0" * pad
        p = self.write("app.asar", header + js + pkg)
        self.assertEqual(call_tool("detect_file_type", {"path": p})["findings"]["format"], "asar")
        r = call_tool("analyze_javascript_application", {"path": p})["findings"]
        self.assertEqual(r["container"], "asar")
        self.assertEqual(r["package"]["name"], "x")
        self.assertEqual(r["ipc"]["channels"][0]["channel"], "ping")

    def test_apk(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("AndroidManifest.xml", build_axml())
            dex = bytearray(112)
            dex[:8] = b"dex\n035\0"
            struct.pack_into("<I", dex, 0x58, 10)
            struct.pack_into("<I", dex, 0x60, 3)
            z.writestr("classes.dex", bytes(dex))
            z.writestr("lib/arm64-v8a/libflutter.so", b"x")
            z.writestr("META-INF/CERT.RSA", b"x")
        r = call_tool("inspect_apk", {"path": self.write("a.apk", buf.getvalue())})["findings"]
        self.assertEqual(r["manifest"]["package"], "com.example.app")
        self.assertEqual(r["manifest"]["version_name"], "1.2.3")
        self.assertEqual(r["manifest"]["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(r["dex"][0]["class_defs"], 3)
        self.assertTrue(r["framework_markers"]["flutter"])


class TestNew(Base):
    def test_fingerprint(self):
        import hashlib
        data = os.urandom(300000) + b"UPX!" + b"\0" * 1000
        r = call_tool("fingerprint_file", {"path": self.write("f.bin", data)})["findings"]
        self.assertEqual(r["sha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("UPX", r["packer_markers"])
        self.assertGreater(r["mean_entropy"], 6)

    def test_embedded(self):
        data = b"\0" * 10 + b"PK\x03\x04" + b"\0" * 20 + b"\x1f\x8b\x08\x00" + b"\0" * 8 + b"\x89PNG\r\n\x1a\n"
        r = call_tool("find_embedded_files", {"path": self.write("e.bin", data)})["findings"]
        self.assertEqual([(h["type"], h["offset"]) for h in r["hits"]], [("zip", 10), ("gzip", 34), ("png", 46)])

    def test_indicators_mask_secrets(self):
        key = b"AKIA" + b"ABCDEFGHIJKLMNOP"
        data = b"\0http://evil.example/path\0contact dev@example.com\0" + key + b"\0" + bytes.fromhex("637c777bf26b6fc5") + b"192.168.1.20\0"
        out = call_tool("extract_indicators", {"path": self.write("i.bin", data)})
        f = out["findings"]
        self.assertEqual(f["indicators"]["urls"], ["http://evil.example/path"])
        self.assertEqual(f["indicators"]["emails"], ["dev@example.com"])
        self.assertIn("192.168.1.20", f["indicators"]["ipv4"])
        self.assertEqual(f["crypto_constants"][0]["algorithm_hint"], "AES S-box")
        self.assertNotIn(key.decode(), json.dumps(out))
        self.assertIn("aws_access_key_id", f["secret_candidates"])

    @unittest.skipUnless(sys.platform.startswith("linux") and os.path.exists("/bin/ls"), "needs Linux ELF")
    def test_elf_symbols(self):
        r = call_tool("inspect_elf_symbols", {"path": os.path.realpath("/bin/ls")})["findings"]
        names = {s["name"] for s in r["symbols"][".dynsym"]["imported"]}
        self.assertTrue(any(n.startswith(("malloc", "free", "__libc")) for n in names))

    def test_wasm(self):
        imp = bytes([1, 3]) + b"env" + bytes([3]) + b"log" + bytes([0, 0])
        exp = bytes([1, 3]) + b"run" + bytes([0, 0])
        data = b"\0asm\x01\0\0\0" + bytes([2, len(imp)]) + imp + bytes([7, len(exp)]) + exp
        r = call_tool("inspect_wasm", {"path": self.write("a.wasm", data)})["findings"]
        self.assertEqual(r["imports"][0], {"module": "env", "name": "log", "kind": "func"})
        self.assertEqual(r["exports"][0]["name"], "run")

    def test_jar(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: com.x.Main\r\n\r\n")
            z.writestr("com/x/Main.class", b"\xca\xfe\xba\xbe\0\0\0\x34rest")
        p = self.write("a.jar", buf.getvalue())
        self.assertEqual(call_tool("detect_file_type", {"path": p})["findings"]["format"], "jar")
        r = call_tool("inspect_jar", {"path": p})["findings"]
        self.assertEqual(r["main_class"], "com.x.Main")
        self.assertEqual(r["java_release_guess"], 8)

    def test_full_report(self):
        r = call_tool("full_report", {"path": self.write("a.exe", build_pe())})["findings"]
        self.assertEqual(r["format"], "pe")
        self.assertEqual(r["analyzers_run"][0], "inspect_pe")
        self.assertNotIn("error", r["sections"]["fingerprint_file"])
        self.assertIn("inspect_go_buildinfo", r["sections"])


class TestMcp(Base):
    def test_protocol(self):
        p = self.write("s.bin", b"hello_world_string")
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "extract_strings", "arguments": {"path": p}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "inspect_pe", "arguments": {"path": p}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
        ]
        out = io.StringIO()
        serve(io.StringIO("\n".join(json.dumps(x) for x in lines) + "\nnot json\n"), out)
        resp = [json.loads(l) for l in out.getvalue().splitlines()]
        by_id = {r.get("id"): r for r in resp}
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "binxray")
        self.assertEqual(len(by_id[2]["result"]["tools"]), 18)
        self.assertFalse(by_id[3]["result"]["isError"])
        self.assertTrue(by_id[4]["result"]["isError"])
        self.assertEqual(by_id[5]["error"]["code"], -32601)
        self.assertEqual(by_id[None]["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
