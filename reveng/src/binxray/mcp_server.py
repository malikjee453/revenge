"""Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0), standard library only."""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, TextIO

from . import __version__
from .registry import TOOLS, call_tool
from .util import ReaError

DEFAULT_PROTOCOL = "2025-06-18"


def _error(id_: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method, id_ = msg.get("method"), msg.get("id")
    is_notification = "id" not in msg
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion") or DEFAULT_PROTOCOL
        return {"jsonrpc": "2.0", "id": id_, "result": {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "binxray", "version": __version__},
            "instructions": "Static, read-only analysis tools. Every result lists its evidence and limitations; report both.",
        }}
    if is_notification:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": id_, "result": {}}
    if method == "tools/list":
        tools = [{"name": t.name, "description": t.description, "inputSchema": t.schema} for t in TOOLS.values()]
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": tools}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in TOOLS:
            return _error(id_, -32602, f"Unknown tool: {name}")
        try:
            out = call_tool(name, args)
            return {"jsonrpc": "2.0", "id": id_, "result": {
                "content": [{"type": "text", "text": json.dumps(out, indent=2, default=str)}],
                "structuredContent": out, "isError": False}}
        except ReaError as exc:
            return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": str(exc)}], "isError": True}}
        except Exception as exc:  # never crash the server on a bad target
            return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": f"Internal error: {type(exc).__name__}: {exc}"}], "isError": True}}
    return _error(id_, -32601, f"Method not found: {method}")


def serve(stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                raise ValueError("request must be an object")
        except ValueError:
            resp: Optional[Dict[str, Any]] = _error(None, -32700, "Parse error")
        else:
            resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, default=str) + "\n")
            stdout.flush()
