"""Indicator extraction: URLs, IPs, emails, paths, registry keys, masked secrets and crypto constants."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..registry import tool
from ..util import open_mmap, result

MAX_SCAN = 128 * 1024 * 1024
CAP = 200
RX = {
    "urls": re.compile(rb"https?://[\x21-\x7e]{4,200}"),
    "ipv4": re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "emails": re.compile(rb"[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,255}\.[A-Za-z]{2,10}"),
    "windows_paths": re.compile(rb"[A-Za-z]:\\(?:[\w .$-]+\\)*[\w .$-]+"),
    "registry_keys": re.compile(rb"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\x20-\x7e]{3,200}"),
    "unix_paths": re.compile(rb"/(?:etc|tmp|var|usr|bin|proc|dev|opt)/[\w./-]{2,100}"),
}
SECRETS = {
    "aws_access_key_id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
}
CRYPTO = [
    ("AES S-box", bytes.fromhex("637c777bf26b6fc5")), ("SHA-256 constants", bytes.fromhex("982f8a42")),
    ("MD5 constants", bytes.fromhex("78a46ad7")), ("CRC32 table", bytes.fromhex("0000000096300777")),
    ("ChaCha/Salsa sigma", b"expand 32-byte k"),
]


def _mask(v: bytes) -> str:
    t = v.decode("ascii", "replace")
    return f"{t[:4]}…({len(t)} chars)"


@tool("extract_indicators", "Extract indicators from any file: URLs, IPv4s, emails, paths, registry keys, masked secret candidates (AWS, GitHub, JWT...) and crypto-constant offsets.")
def extract_indicators(path: str):
    found: Dict[str, List[str]] = {}
    secrets: Dict[str, List[Dict[str, Any]]] = {}
    crypto: List[Dict[str, Any]] = []
    with open_mmap(path) as m:
        scan = m[: min(len(m), MAX_SCAN)] if len(m) > MAX_SCAN else m
        truncated = len(m) > MAX_SCAN
        for key, rx in RX.items():
            seen: List[str] = []
            for mt in rx.finditer(scan):
                v = mt.group(0).decode("ascii", "replace")
                if key == "ipv4" and (v.startswith("0.") or v == "255.255.255.255"):
                    continue
                if v not in seen:
                    seen.append(v)
                if len(seen) >= CAP:
                    break
            if seen:
                found[key] = seen
        for key, rx in SECRETS.items():
            rows = []
            for mt in rx.finditer(scan):
                rows.append({"offset": mt.start(), "masked": "(block header)" if key == "private_key_block" else _mask(mt.group(0))})
                if len(rows) >= 50:
                    break
            if rows:
                secrets[key] = rows
        for name, needle in CRYPTO:
            pos = scan.find(needle)
            if pos != -1:
                crypto.append({"algorithm_hint": name, "first_offset": pos})
    return result(
        "extract_indicators", path,
        {"scan_truncated": truncated, "indicators": found, "secret_candidates": secrets, "crypto_constants": crypto,
         "counts": {k: len(v) for k, v in found.items()}},
        [{"kind": "regex-scan", "detail": "ASCII regex scan over the file bytes; secret values are masked in the output."}],
        ["ASCII only: UTF-16 and obfuscated/encrypted strings are not seen.",
         f"Only the first {MAX_SCAN // 1024 // 1024} MiB is scanned; at most {CAP} unique values per category.",
         "Secret candidates are pattern matches and may be test values or false positives; rotate real ones.",
         "Crypto constants show that an algorithm's tables exist in the file, not how or whether they are used."],
    )
