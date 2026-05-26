from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import Config
from app.seed_loader import load_seed_data

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _apply_compat_migrations(conn: sqlite3.Connection) -> None:
    sample_columns = _table_columns(conn, "samples")
    if "zeek_summary_json" not in sample_columns:
        conn.execute("ALTER TABLE samples ADD COLUMN zeek_summary_json TEXT")
    if "parse_summary_json" not in sample_columns:
        conn.execute("ALTER TABLE samples ADD COLUMN parse_summary_json TEXT")


def init_db() -> None:
    db_path = Config.DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(schema_sql)
        _apply_compat_migrations(conn)
        load_seed_data(conn)
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    init_db()


if __name__ == "__main__":
    main()
