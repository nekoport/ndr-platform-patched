"""Regression guard: postgres/init/001_schema.sql must stay in sync with the
SQLAlchemy ORM (app.models).

Why: 0.12.2 shipped `users.id UUID` in the SQL schema while the ORM used
String(36). SQLite (used by this test suite) ignores the mismatch, but real
Postgres rejects every ORM INSERT with
`column "id" is of type uuid but expression is of type character varying`.
These tests parse the schema DDL statically so the drift is caught on CI
without needing a Postgres server.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import String  # noqa: E402

from app.db import Base  # noqa: E402
from app import models  # noqa: E402,F401  (import registers tables)

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "postgres" / "init" / "001_schema.sql"

# ORM column python/sqlalchemy type -> acceptable Postgres declared types.
TYPE_CLASSES = {
    "string": {"TEXT", "VARCHAR", "CHAR"},
    "integer": {"INT", "INTEGER", "BIGINT", "SMALLINT", "SERIAL", "BIGSERIAL"},
    "boolean": {"BOOLEAN", "BOOL"},
    "datetime": {"TIMESTAMPTZ", "TIMESTAMP", "TIMESTAMPTZ[]"},
    "json": {"JSONB", "JSON"},
    "numeric": {"NUMERIC", "DECIMAL", "DOUBLE PRECISION", "REAL", "BIGINT"},
}


def _orm_kind(col) -> str:
    py = col.type.python_type.__name__ if col.type.python_type else ""
    if py == "str":
        return "string"
    if py == "int":
        return "integer"
    if py == "bool":
        return "boolean"
    if py == "datetime":
        return "datetime"
    if py in ("dict", "list"):
        return "json"
    if py in ("float", "Decimal"):
        return "numeric"
    return "unknown"


_TABLE_RE = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)\s*\((.*?)\n\);", re.S)
_COLNAME_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_CONSTRAINT_STARTERS = {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"}


def _parse_schema_columns() -> dict[str, dict[str, str]]:
    """Return {table: {column: declared_type}} from the schema DDL."""
    ddl = SCHEMA_PATH.read_text()
    tables: dict[str, dict[str, str]] = {}
    for name, body in _TABLE_RE.findall(ddl):
        cols: dict[str, str] = {}
        for line in body.splitlines():
            s = line.strip().rstrip(",")
            if not s or s.startswith("--"):
                continue
            first_word = s.split(None, 1)[0].upper()
            if first_word in _CONSTRAINT_STARTERS:
                continue
            parts = s.split()
            # column lines look like:  name TYPE [modifiers...]
            # (type is a single token in this schema: TEXT, VARCHAR(36), INT,
            #  BIGINT, BOOLEAN, TIMESTAMPTZ, JSONB, TEXT[], ...)
            if len(parts) < 2 or not _COLNAME_RE.match(parts[0]):
                continue  # CHECK-constraint continuation lines like 'role IN (...'
            if not parts[1][0].isalpha():
                continue
            cols[parts[0].lower()] = parts[1].upper()
        tables[name] = cols
    return tables


@pytest.fixture(scope="module")
def schema_tables() -> dict[str, dict[str, str]]:
    assert SCHEMA_PATH.exists(), f"schema file missing: {SCHEMA_PATH}"
    parsed = _parse_schema_columns()
    assert parsed, "schema DDL parse produced no tables - parser broken?"
    return parsed


def test_no_uuid_column_types_left_in_schema(schema_tables):
    """ORM uses String(36) ids everywhere; Postgres UUID type must not return."""
    for table, cols in schema_tables.items():
        for colname, ctype in cols.items():
            base = ctype.split("(")[0].strip()
            assert base != "UUID", (
                f"{table}.{colname} is declared {ctype} in 001_schema.sql but the ORM "
                f"writes VARCHAR(36) strings - this breaks real Postgres inserts"
            )


def test_orm_tables_exist_in_schema(schema_tables):
    """Every ORM table must exist in the SQL schema.

    Note: the schema may legitimately contain extra tables provisioned from
    the design doc but not yet mapped in the ORM (subnets, update_jobs,
    maintenance_jobs) - those are accessed via raw SQL or reserved for later
    phases and are not an error.
    """
    orm_tables = set(Base.metadata.tables.keys())
    sql_tables = set(schema_tables.keys())
    missing_in_sql = orm_tables - sql_tables
    assert not missing_in_sql, (
        f"tables in ORM but missing from 001_schema.sql: {sorted(missing_in_sql)}"
    )


def test_primary_key_types_match(schema_tables):
    """PK columns: string PKs must be TEXT/VARCHAR, integer PKs integer types."""
    for table, orm_t in Base.metadata.tables.items():
        sql_cols = schema_tables.get(table, {})
        for colname, col in orm_t.columns.items():
            if not col.primary_key:
                continue
            assert colname in sql_cols, f"{table}.{colname} (ORM PK) missing from schema"
            base = sql_cols[colname].split("(")[0].strip()
            kind = _orm_kind(col)
            if kind == "string":
                assert base in TYPE_CLASSES["string"], (
                    f"PK {table}.{colname}: ORM declares a string PK but schema says "
                    f"{sql_cols[colname]} - must be TEXT/VARCHAR"
                )
            elif kind == "integer":
                assert base in TYPE_CLASSES["integer"], (
                    f"PK {table}.{colname}: ORM declares an integer PK but schema says "
                    f"{sql_cols[colname]} - must be INT/BIGINT/SERIAL-family"
                )


def test_common_column_types_match(schema_tables):
    """Shared columns must use compatible type classes (catches future drift)."""
    checked = 0
    for table, orm_t in Base.metadata.tables.items():
        sql_cols = schema_tables.get(table, {})
        for colname, col in orm_t.columns.items():
            if colname not in sql_cols:
                continue
            kind = _orm_kind(col)
            if kind == "unknown":
                continue
            base = sql_cols[colname].split("(")[0].strip()
            allowed = TYPE_CLASSES[kind]
            assert base in allowed, (
                f"{table}.{colname}: ORM type maps to {kind} but schema declares "
                f"{sql_cols[colname]} (expected one of {sorted(allowed)})"
            )
            checked += 1
    assert checked > 40, f"type cross-check covered only {checked} columns - parser regression?"
