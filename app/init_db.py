from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import Config
from app.seed_loader import load_seed_data

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def init_db() -> None:
    db_path = Config.DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(schema_sql)
        load_seed_data(conn)
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    init_db()


if __name__ == "__main__":
    main()
