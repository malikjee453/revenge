"""SQLite schema inspection (read-only)."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List

from ..registry import tool
from ..util import ReaError, resolve_file, result

MAX_SAMPLE_ROWS = 20


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _cell(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return {"blob_bytes": len(v), "hex_prefix": bytes(v[:16]).hex()}
    if isinstance(v, str) and len(v) > 200:
        return v[:200] + "…"
    return v


@tool(
    "inspect_sqlite",
    "Inspect a SQLite database read-only: tables, columns, indexes, views, triggers, optional row counts and sample rows.",
    {
        "include_row_counts": {"type": "boolean", "description": "Count rows per table (can be slow on large tables)."},
        "sample_table": {"type": "string", "description": "Table name to return sample rows from."},
        "sample_rows": {"type": "integer", "description": f"Sample row count (default 5, max {MAX_SAMPLE_ROWS})."},
    },
)
def inspect_sqlite(path: str, include_row_counts: bool = False, sample_table: str = "", sample_rows: int = 5):
    p = resolve_file(path)
    con = sqlite3.connect(p.as_uri() + "?mode=ro", uri=True)
    try:
        con.execute("PRAGMA query_only=ON")
        try:
            objs = con.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()
        except sqlite3.DatabaseError as exc:
            raise ReaError(f"Not a readable SQLite database: {exc}")
        tables: List[Dict[str, Any]] = []
        for typ, name, _tbl, sql in objs:
            if typ != "table":
                continue
            cols = con.execute(f"PRAGMA table_info({_quote(name)})").fetchall()
            t: Dict[str, Any] = {
                "name": name,
                "columns": [{"name": c[1], "type": c[2], "not_null": bool(c[3]), "primary_key": bool(c[5])} for c in cols],
                "sql": sql,
            }
            if include_row_counts:
                t["row_count"] = con.execute(f"SELECT COUNT(*) FROM {_quote(name)}").fetchone()[0]
            tables.append(t)
        findings: Dict[str, Any] = {
            "page_size": con.execute("PRAGMA page_size").fetchone()[0],
            "page_count": con.execute("PRAGMA page_count").fetchone()[0],
            "encoding": con.execute("PRAGMA encoding").fetchone()[0],
            "user_version": con.execute("PRAGMA user_version").fetchone()[0],
            "tables": tables,
            "indexes": [{"name": n, "table": t, "sql": s} for ty, n, t, s in objs if ty == "index"],
            "views": [{"name": n, "sql": s} for ty, n, _t, s in objs if ty == "view"],
            "triggers": [{"name": n, "table": t, "sql": s} for ty, n, t, s in objs if ty == "trigger"],
        }
        if sample_table:
            if sample_table not in {t["name"] for t in tables}:
                raise ReaError(f"No such table: {sample_table}")
            n = max(1, min(sample_rows, MAX_SAMPLE_ROWS))
            cur = con.execute(f"SELECT * FROM {_quote(sample_table)} LIMIT {int(n)}")
            names = [d[0] for d in cur.description]
            findings["sample"] = {"table": sample_table, "rows": [{k: _cell(v) for k, v in zip(names, row)} for row in cur.fetchall()]}
    finally:
        con.close()
    return result(
        "inspect_sqlite", path, findings,
        [{"kind": "sqlite_master", "detail": "Schema read from sqlite_master and PRAGMAs over a read-only connection."}],
        ["Opened read-only; an unmerged -wal file next to the database may hold newer rows than the main file.",
         f"Sample rows are capped at {MAX_SAMPLE_ROWS}; long text is truncated and blobs are summarized.",
         "Encrypted databases (e.g. SQLCipher) cannot be read."],
    )
