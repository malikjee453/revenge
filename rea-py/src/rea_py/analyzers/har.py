"""HAR (HTTP Archive) capture summary. Header and body values are never returned."""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import urlsplit

from ..registry import tool
from ..util import ReaError, resolve_file, result

MAX_FILE = 256 * 1024 * 1024


@tool(
    "inspect_har",
    "Summarize a HAR network capture: hosts, methods, status codes, content types and API-like requests. Header and body values are not returned.",
    {"max_entries": {"type": "integer", "description": "Maximum request rows to return (default 100, max 1000)."}},
)
def inspect_har(path: str, max_entries: int = 100):
    p = resolve_file(path)
    if p.stat().st_size > MAX_FILE:
        raise ReaError("HAR file too large")
    try:
        log = json.loads(p.read_text(encoding="utf-8-sig"))["log"]
        entries = log["entries"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReaError(f"Not a valid HAR file: {exc}")
    max_entries = max(1, min(max_entries, 1000))
    hosts, methods, statuses, mimes = Counter(), Counter(), Counter(), Counter()
    rows: List[Dict[str, Any]] = []
    api_like = 0
    sensitive = 0
    for i, e in enumerate(entries):
        req, resp = e.get("request", {}), e.get("response", {})
        url = req.get("url", "")
        parts = urlsplit(url)
        mime = (resp.get("content", {}).get("mimeType") or "").split(";")[0]
        hosts[parts.netloc] += 1
        methods[req.get("method", "?")] += 1
        statuses[resp.get("status", 0)] += 1
        mimes[mime or "unknown"] += 1
        is_api = "json" in mime or "/api/" in parts.path.lower() or "graphql" in parts.path.lower()
        api_like += is_api
        hdr_names = {h.get("name", "").lower() for h in req.get("headers", [])}
        has_auth = bool(hdr_names & {"authorization", "cookie", "x-api-key"})
        sensitive += has_auth
        if i < max_entries:
            rows.append({
                "index": i, "method": req.get("method"), "scheme_host": f"{parts.scheme}://{parts.netloc}",
                "path": parts.path, "has_query": bool(parts.query), "status": resp.get("status"),
                "mime_type": mime, "body_size": resp.get("content", {}).get("size"),
                "time_ms": e.get("time"), "carries_credentials_headers": has_auth, "api_like": is_api,
            })
    findings = {
        "creator": log.get("creator", {}).get("name"), "entry_count": len(entries),
        "hosts": dict(hosts.most_common(50)), "methods": dict(methods), "status_codes": {str(k): v for k, v in statuses.items()},
        "content_types": dict(mimes.most_common(30)), "api_like_requests": api_like,
        "requests_with_credential_headers": sensitive, "requests_listed": len(rows), "requests": rows,
    }
    return result(
        "inspect_har", path, findings,
        [{"kind": "har-entries", "detail": "Counted from log.entries; query strings and header/body values are withheld."}],
        ["'api_like' is a heuristic (JSON mime type, /api/ or graphql in path).",
         "Credential header presence is reported as a boolean only; values are never emitted.",
         "HAR files can omit bodies or be incomplete if the capture was filtered."],
    )
