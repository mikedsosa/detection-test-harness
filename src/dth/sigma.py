"""Run Sigma rules with pySigma's SQLite backend against flattened synthetic events.

The same synthetic rows the KQL rules see are flattened into one SQLite table
named ``logs``, which is what the SQLite backend queries:

* scalar columns are copied as-is;
* a dynamic (JSON) column is stored as its JSON text under its own name, and
  its nested keys are also exposed with dotted names (``Status.additionalDetails``);
  for a list, only the first element is expanded (``TargetResources.userPrincipalName``);
* ``timestamp`` is TimeGenerated as ISO 8601 text, used by correlation rules.

Field names are matched case-insensitively because SQLite identifiers are, so a
Sigma field ``riskLevel`` reads the Sentinel column ``RiskLevel``. There is no
other field mapping. Text columns are declared ``COLLATE NOCASE`` so ``=``
matches the way Sigma's default, case-insensitive, string match does.

The backend does not filter by logsource, so the harness loads only the tables
mapped to the rule's logsource (see ``LOGSOURCE_TABLES``).
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from dth.schema import COLUMNS, dynamic_columns

#: The harness's own mapping from Sigma logsource to Sentinel tables.
LOGSOURCE_TABLES: dict[tuple[str | None, str | None], tuple[str, ...]] = {
    ("azure", "signinlogs"): ("SigninLogs",),
    ("azure", "auditlogs"): ("AuditLogs",),
    ("azure", "riskdetection"): ("AADUserRiskEvents",),
    ("m365", "audit"): ("OfficeActivity",),
}


class MissingField(Exception):
    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _flatten(table: str, row: dict) -> dict:
    out: dict = {"timestamp": row["TimeGenerated"].isoformat()}
    dyn = dynamic_columns(table)
    for col in COLUMNS[table]:
        value = row[col]
        if col in dyn:
            if isinstance(value, str):
                value = json.loads(value)
            out[col] = json.dumps(value)
            first = value[0] if isinstance(value, list) and value else value
            if isinstance(first, dict):
                _expand(out, col, first)
        elif isinstance(value, datetime):
            out[col] = value.isoformat()
        else:
            out[col] = value
    return out


def _expand(out: dict, prefix: str, obj: dict) -> None:
    for key, value in obj.items():
        name = f"{prefix}.{key}"
        if isinstance(value, dict):
            _expand(out, name, value)
        elif isinstance(value, list):
            out[name] = json.dumps(value)
        else:
            out[name] = value


def events_for(tables: tuple[str, ...], rows: dict[str, list[dict]]) -> list[dict]:
    events = []
    for table in tables:
        events.extend(_flatten(table, r) for r in rows.get(table, []))
    return events


def _load_db(events: list[dict]) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    columns: dict[str, str] = {}
    for event in events:
        for key in event:
            folded = key.lower()
            if folded in columns and columns[folded] != key:
                raise ValueError(f"field names collide when case-folded: {columns[folded]} / {key}")
            columns[folded] = key
    names = list(columns.values()) or ["timestamp"]
    ddl = ", ".join(f'"{n}" TEXT COLLATE NOCASE' for n in names)
    con.execute(f"CREATE TABLE logs ({ddl})")
    quoted = ", ".join(f'"{n}"' for n in names)
    marks = ", ".join("?" for _ in names)
    con.executemany(
        f"INSERT INTO logs ({quoted}) VALUES ({marks})",
        [[e.get(n) for n in names] for e in events],
    )
    return con


def tables_for(collection: SigmaCollection) -> tuple[str, ...]:
    tables: list[str] = []
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            continue
        key = (rule.logsource.product, rule.logsource.service)
        if key not in LOGSOURCE_TABLES:
            raise KeyError(f"no table mapping for logsource {key}")
        for t in LOGSOURCE_TABLES[key]:
            if t not in tables:
                tables.append(t)
    return tuple(tables)


def convert(paths: list[Path]) -> tuple[SigmaCollection, list[str]]:
    collection = SigmaCollection.load_ruleset([str(p) for p in paths])
    return collection, sqliteBackend().convert(collection)


def run(paths: list[Path], rows: dict[str, list[dict]]) -> tuple[list[dict], list[str]]:
    collection, queries = convert(paths)
    con = _load_db(events_for(tables_for(collection), rows))
    con.row_factory = sqlite3.Row
    # A correlation collection converts to one query for the correlation; a plain
    # rule set converts to one query per rule. Run the last query, which is the
    # correlation when there is one and the only rule otherwise.
    if len(queries) != 1 and not any(isinstance(r, SigmaCorrelationRule) for r in collection.rules):
        raise ValueError("expected exactly one detection rule per run")
    sql = queries[-1]
    try:
        result = [dict(r) for r in con.execute(sql).fetchall()]
    except sqlite3.OperationalError as exc:
        match = re.search(r"no such column: (.+)$", str(exc))
        if match:
            raise MissingField(match.group(1).strip('`"')) from exc
        raise
    finally:
        con.close()
    return result, queries
