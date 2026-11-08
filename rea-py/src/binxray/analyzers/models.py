"""Model artifact headers: GGUF and safetensors (metadata only, tensors are never loaded)."""
from __future__ import annotations

import json
import struct
from typing import Any, Dict, List, Tuple

from ..registry import tool
from ..util import ReaError, open_mmap, result

GGUF_TYPES = {0: "u8", 1: "i8", 2: "u16", 3: "i16", 4: "u32", 5: "i32", 6: "f32", 7: "bool", 8: "string",
              9: "array", 10: "u64", 11: "i64", 12: "f64"}
GGUF_FMT = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
GGML_TYPES = {0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1", 8: "Q8_0", 9: "Q8_1", 10: "Q2_K",
              11: "Q3_K", 12: "Q4_K", 13: "Q5_K", 14: "Q6_K", 15: "Q8_K", 24: "I8", 25: "I16", 26: "I32",
              27: "I64", 28: "F64", 30: "BF16"}
MAX_KV = 8192
MAX_TENSORS_LISTED = 200
MAX_ARRAY_SAMPLE = 8


class _R:
    def __init__(self, m: Any, pos: int = 0):
        self.m, self.pos = m, pos

    def unpack(self, fmt: str):
        v = struct.unpack_from(fmt, self.m, self.pos)
        self.pos += struct.calcsize(fmt)
        return v[0] if len(v) == 1 else v

    def string(self) -> str:
        n = self.unpack("<Q")
        if n > 16 * 1024 * 1024 or self.pos + n > len(self.m):
            raise ReaError("GGUF string length out of range")
        s = bytes(self.m[self.pos : self.pos + n]).decode("utf-8", "replace")
        self.pos += n
        return s

    def value(self, t: int):
        if t == 8:
            return self.string()
        if t == 9:
            et, n = self.unpack("<I"), self.unpack("<Q")
            sample = []
            for i in range(n):
                v = self.value(et)
                if i < MAX_ARRAY_SAMPLE:
                    sample.append(v)
            return {"array_of": GGUF_TYPES.get(et, et), "length": n, "sample": sample}
        if t not in GGUF_FMT:
            raise ReaError(f"Unknown GGUF value type {t}")
        return self.unpack(GGUF_FMT[t])


def parse_gguf(m: Any) -> Dict[str, Any]:
    r = _R(m, 4)
    version = r.unpack("<I")
    if version not in (1, 2, 3):
        raise ReaError(f"Unsupported GGUF version {version}")
    n_tensors, n_kv = (r.unpack("<I"), r.unpack("<I")) if version == 1 else (r.unpack("<Q"), r.unpack("<Q"))
    if n_kv > MAX_KV:
        raise ReaError(f"Implausible GGUF metadata count {n_kv}")
    kv: Dict[str, Any] = {}
    for _ in range(n_kv):
        key = r.string()
        kv[key] = r.value(r.unpack("<I"))
    tensors: List[Dict[str, Any]] = []
    total = 0
    by_type: Dict[str, int] = {}
    for i in range(min(n_tensors, 1_000_000)):
        name = r.string()
        nd = r.unpack("<I")
        if nd > 8:
            raise ReaError("Tensor rank out of range")
        dims = [r.unpack("<Q") for _ in range(nd)]
        ttype, offset = r.unpack("<I"), r.unpack("<Q")
        count = 1
        for d in dims:
            count *= d
        total += count
        tn = GGML_TYPES.get(ttype, f"type_{ttype}")
        by_type[tn] = by_type.get(tn, 0) + count
        if i < MAX_TENSORS_LISTED:
            tensors.append({"name": name, "shape": dims, "type": tn, "offset": offset})
    return {
        "format": "gguf", "version": version, "tensor_count": n_tensors, "metadata_count": n_kv,
        "architecture": kv.get("general.architecture"), "model_name": kv.get("general.name"),
        "metadata": kv, "total_parameters": total, "parameters_by_type": by_type,
        "tensors_listed": len(tensors), "tensors": tensors,
    }


def parse_safetensors(m: Any) -> Dict[str, Any]:
    (hlen,) = struct.unpack_from("<Q", m, 0)
    if hlen > 100 * 1024 * 1024 or 8 + hlen > len(m):
        raise ReaError("safetensors header length out of range")
    header = json.loads(bytes(m[8 : 8 + hlen]).decode("utf-8"))
    meta = header.pop("__metadata__", {})
    data_size = len(m) - 8 - hlen
    tensors: List[Dict[str, Any]] = []
    total = 0
    by_dtype: Dict[str, int] = {}
    problems: List[str] = []
    for name, spec in header.items():
        shape, dtype, (b, e) = spec["shape"], spec["dtype"], spec["data_offsets"]
        count = 1
        for d in shape:
            count *= d
        total += count
        by_dtype[dtype] = by_dtype.get(dtype, 0) + count
        if not 0 <= b <= e <= data_size:
            problems.append(f"{name}: data_offsets [{b}, {e}] outside data region ({data_size} bytes)")
        if len(tensors) < MAX_TENSORS_LISTED:
            tensors.append({"name": name, "dtype": dtype, "shape": shape, "data_offsets": [b, e]})
    return {
        "format": "safetensors", "header_size": hlen, "metadata": meta, "tensor_count": len(header),
        "total_parameters": total, "parameters_by_dtype": by_dtype, "offset_problems": problems,
        "tensors_listed": len(tensors), "tensors": tensors,
    }


@tool("inspect_model_file", "Read GGUF or safetensors headers: metadata, tensor shapes/dtypes and derived parameter totals. Tensor data is never loaded.")
def inspect_model_file(path: str):
    with open_mmap(path) as m:
        if bytes(m[:4]) == b"GGUF":
            info = parse_gguf(m)
        else:
            try:
                info = parse_safetensors(m)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ReaError(f"Not a GGUF or safetensors file ({exc})")
    return result(
        "inspect_model_file", path, info,
        [{"kind": "header", "detail": f"Decoded {info['format']} header only."}],
        [f"At most {MAX_TENSORS_LISTED} tensors are listed; totals cover all declared tensors.",
         "Parameter totals are derived from declared shapes, not verified against tensor bytes."],
    )
