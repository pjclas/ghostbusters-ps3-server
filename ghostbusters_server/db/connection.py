"""SQLite connection + migration runner. PRAGMAs in schema only apply mid-script,
so foreign_keys must be re-enabled per connection."""

import sqlite3
from pathlib import Path

from .. import config


def open_db() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH, isolation_level=None)  # autocommit
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.row_factory = sqlite3.Row
    return con


def apply_migrations(con: sqlite3.Connection) -> None:
    con.execute(
        "CREATE TABLE IF NOT EXISTS _migrations ("
        "name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now')))"
    )
    applied = {r[0] for r in con.execute("SELECT name FROM _migrations")}
    for path in sorted(config.MIGRATIONS_DIR.glob("*.sql")):
        if path.name in applied:
            continue
        con.executescript(path.read_text())
        con.execute("INSERT INTO _migrations(name) VALUES (?)", (path.name,))
        print(f"[db] applied migration {path.name}")


def init_db() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = open_db()
    apply_migrations(con)
    return con
