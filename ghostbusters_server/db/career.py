"""Career-stat + leaderboard persistence (REPLACE store-and-serve).

The client owns all aggregation: it reads the baseline WE serve in the m=9
reply, folds in the match (sum / OR / max / replace, internally), and uploads
the finished career value in the m=12 ReportStats. The server only snapshots
the upload and serves it back — no server-side accumulation. So persistence is
deliberately dumb:

    on m=12:  stored[pid] = uploaded_vec0          (career_stats)
              stored[pid][cat] = uploaded block     (leaderboard_stats)
    on m=9:   reply = stored[pid]

This module is the persistence layer for both tables; the wire shapes it
serves and ingests are defined in the proto-60 handlers (protocols/game.py).
"""

from __future__ import annotations

import sqlite3
import struct
import time

# Length of the career vec0 the client uploads / we serve back. Stored verbatim;
# shorter uploads are zero-padded, longer ones truncated, so the blob is fixed.
VEC0_LEN = 122


def pack_vec0(vec0: list[float]) -> bytes:
    """Pack a vec0 list into a fixed-length little-endian f32 blob."""
    v = list(vec0[:VEC0_LEN]) + [0.0] * max(0, VEC0_LEN - len(vec0))
    return struct.pack("<%df" % VEC0_LEN, *v)


def unpack_vec0(blob: bytes) -> list[float]:
    """Inverse of pack_vec0."""
    n = len(blob) // 4
    return list(struct.unpack("<%df" % n, blob[: n * 4]))


# --- career_stats -----------------------------------------------------------

def get_career(con: sqlite3.Connection, pid: int) -> list[float] | None:
    """Return a single player's stored career vec0, or None if never uploaded.
    This is the authoritative read for the m=9 cat=101/102 reply (the DB is the
    source of truth — there is no server-side cache that could drift ahead)."""
    r = con.execute("SELECT vec0 FROM career_stats WHERE pid=?", (pid,)).fetchone()
    return unpack_vec0(r["vec0"]) if r is not None else None


def career_cash(con: sqlite3.Connection, pid: int) -> float:
    """Career cash (vec0[5]) for one PID, or 0.0 if no row. Cheap helper for the
    m=12 reply baseline + the stats-processed notification."""
    v = get_career(con, pid)
    return v[5] if v is not None and len(v) > 5 else 0.0


def load_all_career(con: sqlite3.Connection) -> dict[int, list[float]]:
    """Return {pid: vec0} for every stored career row."""
    return {int(r["pid"]): unpack_vec0(r["vec0"])
            for r in con.execute("SELECT pid, vec0 FROM career_stats")}


def upsert_career(con: sqlite3.Connection, pid: int, vec0: list[float]) -> None:
    """Store (replace) a player's career vec0."""
    con.execute(
        "INSERT INTO career_stats(pid, vec0, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(pid) DO UPDATE SET vec0=excluded.vec0, "
        "updated_at=excluded.updated_at",
        (pid, pack_vec0(vec0), int(time.time())),
    )


# --- leaderboard_stats ------------------------------------------------------

def get_leaderboard(con: sqlite3.Connection, pid: int,
                    category: int) -> dict | None:
    """A player's stored baseline for one board, or None. Served as the m=9
    cat=20x/30x own-baseline so the client knows its existing high score."""
    r = con.execute(
        "SELECT cash, mode_stat, map_id FROM leaderboard_stats "
        "WHERE pid=? AND category=?", (pid, category)).fetchone()
    if r is None:
        return None
    return {"cash": float(r["cash"]), "mode_stat": float(r["mode_stat"]),
            "map_id": int(r["map_id"])}


def ranked_for_category(con: sqlite3.Connection, category: int) -> list[dict]:
    """All players on a board, ordered by cash descending (every board ranks by
    cash; the mode-stat is a display column). Drives the m=7/m=17 board list.

    Excludes cash=0 rows: every m=12 stores all 6 mode-blocks, so modes a player
    never actually played sit in the table as all-zero entries. They're not real
    high scores and must not appear on the board (a never-played board shows
    empty, not a list of $0 players). Store stays dumb; we just don't RANK zeros."""
    return [
        {"pid": int(r["pid"]), "cash": float(r["cash"]),
         "mode_stat": float(r["mode_stat"]), "map_id": int(r["map_id"])}
        for r in con.execute(
            "SELECT pid, cash, mode_stat, map_id FROM leaderboard_stats "
            "WHERE category=? AND cash > 0 ORDER BY cash DESC", (category,))
    ]


def load_all_leaderboards(con: sqlite3.Connection) -> dict[tuple[int, int], dict]:
    """Return {(pid, category): {cash, mode_stat, map_id}} for all stored rows."""
    out: dict[tuple[int, int], dict] = {}
    for r in con.execute(
        "SELECT pid, category, cash, mode_stat, map_id FROM leaderboard_stats"
    ):
        out[(int(r["pid"]), int(r["category"]))] = {
            "cash": float(r["cash"]),
            "mode_stat": float(r["mode_stat"]),
            "map_id": int(r["map_id"]),
        }
    return out


def upsert_leaderboard(con: sqlite3.Connection, pid: int, category: int,
                       cash: float, mode_stat: float, map_id: int) -> None:
    """Store (replace) a player's baseline for one leaderboard category."""
    con.execute(
        "INSERT INTO leaderboard_stats"
        "(pid, category, cash, mode_stat, map_id, updated_at) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(pid, category) DO UPDATE SET cash=excluded.cash, "
        "mode_stat=excluded.mode_stat, map_id=excluded.map_id, "
        "updated_at=excluded.updated_at",
        (pid, category, float(cash), float(mode_stat), int(map_id), int(time.time())),
    )
