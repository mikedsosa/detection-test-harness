"""Run KQL against synthetic tables with duckdb-kql (KQL translated to DuckDB SQL).

This is not the Kusto engine. duckdb-kql parses KQL with an ANTLR grammar
generated from Microsoft's KQL grammar and translates it to DuckDB SQL. A
construct it cannot translate raises ``KqlUnsupportedError``; the harness
reports that as ENGINE_UNSUPPORTED instead of guessing.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import duckdb_kql
import yaml

from dth.scenarios import NOW
from dth.schema import COLUMNS, duckdb_ddl, dynamic_columns


def load_query(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text)["query"]
    return text


def connect(rows: dict[str, list[dict]]):
    con = duckdb_kql.connect()
    for table in COLUMNS:
        con.execute(duckdb_ddl(table))
        dyn = dynamic_columns(table)
        cols = COLUMNS[table]
        placeholders = ", ".join("?" for _ in cols)
        for row in rows.get(table, []):
            missing = set(row) ^ set(cols)
            if missing:
                raise ValueError(f"{table} row has mismatched columns: {sorted(missing)}")
            values = [json.dumps(row[c]) if c in dyn else row[c] for c in cols]
            con.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', values)
    return con


def run(query: str, rows: dict[str, list[dict]], now: datetime = NOW) -> list[dict]:
    con = connect(rows)
    try:
        rel = duckdb_kql.query(con, query, query_now=now)
        names = rel.columns
        return [dict(zip(names, rec, strict=True)) for rec in rel.fetchall()]
    finally:
        con.close()
