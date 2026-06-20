"""Account allocation. find_or_create_account is the only entry the auth layer needs."""

from __future__ import annotations

import sqlite3
import time


def find_or_create_account(con: sqlite3.Connection, psn_id: str) -> int:
    """Return the PID for this psn_id, creating an account if necessary."""
    now = int(time.time())
    row = con.execute("SELECT pid FROM accounts WHERE psn_id = ?", (psn_id,)).fetchone()
    if row is not None:
        con.execute("UPDATE accounts SET last_login_at = ? WHERE pid = ?", (now, row[0]))
        return int(row[0])

    con.execute("BEGIN IMMEDIATE")
    try:
        pid_row = con.execute("SELECT value FROM counters WHERE name = 'next_pid'").fetchone()
        pid = int(pid_row[0])
        con.execute("UPDATE counters SET value = value + 1 WHERE name = 'next_pid'")
        con.execute(
            "INSERT INTO accounts (pid, psn_id, created_at, last_login_at) VALUES (?, ?, ?, ?)",
            (pid, psn_id, now, now),
        )
        con.execute("COMMIT")
        return pid
    except Exception:
        con.execute("ROLLBACK")
        raise


def name_for_pid(con: sqlite3.Connection, pid: int) -> str:
    """Return the psn_id for a PID, or a fallback string."""
    row = con.execute("SELECT psn_id FROM accounts WHERE pid = ?", (pid,)).fetchone()
    return row[0] if row else f"PID{pid}"
