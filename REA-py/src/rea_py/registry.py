"""Tool registry used by both the CLI and the MCP server."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .util import ReaError


@dataclass
class Tool:
    name: str
    description: str
    schema: Dict[str, Any]
    func: Callable[..., Dict[str, Any]]


TOOLS: Dict[str, Tool] = {}


def tool(
    name: str,
    description: str,
    properties: Optional[Dict[str, Dict[str, Any]]] = None,
    path_description: str = "Absolute path to the target file.",
):
    props: Dict[str, Any] = {"path": {"type": "string", "description": path_description}}
    props.update(properties or {})

    def deco(fn: Callable[..., Dict[str, Any]]):
        TOOLS[name] = Tool(
            name=name,
            description=description,
            schema={
                "type": "object",
                "properties": props,
                "required": ["path"],
                "additionalProperties": False,
            },
            func=fn,
        )
        return fn

    return deco


_TYPES = {"string": str, "integer": int, "boolean": bool, "number": (int, float)}


def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    t = TOOLS.get(name)
    if t is None:
        raise ReaError(f"Unknown tool: {name}")
    props = t.schema["properties"]
    unknown = set(args) - set(props)
    if unknown:
        raise ReaError(f"Unknown argument(s): {', '.join(sorted(unknown))}")
    if "path" not in args:
        raise ReaError("Missing required argument: path")
    for key, value in args.items():
        expected = _TYPES.get(props[key].get("type", "string"))
        if expected and (not isinstance(value, expected) or (expected is int and isinstance(value, bool))):
            raise ReaError(f"Argument '{key}' must be of type {props[key].get('type')}")
    try:
        return t.func(**args)
    except (struct.error, IndexError, ValueError, UnicodeError) as exc:
        raise ReaError(f"Target is truncated or malformed ({type(exc).__name__}: {exc})") from exc
