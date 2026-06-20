"""Ghostbusters game-specific protocol (proto 60): matchmaking + stats.

This is the main game protocol. It carries two largely independent concerns:

  Matchmaking — create / browse / join / leave gatherings (lobbies), plus the
  match-lifecycle calls the host fires around match-start and match-end:
     4 CreateGathering      → returns u32 new gathering_id; one gathering per PID
     5 JoinGathering        → host URLs + participant block + embedded gathering
    16 LeaveGathering       → caller leaves the gathering (host and guest both call)
    19 CloseParticipation   → host locks the lobby (countdown-start / match-end)
    20 SearchGatherings     → filtered list of joinable gatherings
    21 QuickMatch           → first matching open gathering, as a 1-element list
    23 OpenParticipation    → host re-opens a locked lobby
    26 lifecycle (no-op)    → fires after m=19 at match-start
    15 EndGame              → unranked match end (no stats reported)

  Stats — leaderboards and career persistence:
     7 GetLeaderboardStatsAroundSelf  → window centered on the requester ("Personal")
     9 ReadStats                      → per-user career blob (Player Stats / MWG)
    12 ReportStats                    → match-end career upload from each player
    17 GetLeaderboardStats            → top-N global leaderboard page ("Global")
    10 / 22 friends / invitations     → social menu lists (empty stub)

Stats persistence is store-and-serve: the client owns all aggregation and
uploads finished career totals in m=12; the server stores them and serves them
back in m=9 / leaderboard replies. See db/career.py for the storage layer.
"""

from __future__ import annotations

import logging
import struct

from ..rmc.codec import Request, ResponseError, ResponseOK
from ..rmc import types as rt
from ..state.gatherings import gatherings
from ..db import accounts
from ..db import career
from .. import db
from . import notification

log = logging.getLogger("game")

PROTO = 60
METHOD_CREATE_GATHERING  = 4
METHOD_JOIN_GATHERING    = 5
METHOD_LEADERBOARD_SELF  = 7    # GetLeaderboardStatsAroundSelf — window centered on requester's rank
METHOD_USER_STATS        = 9    # full per-user stats blob (Player Stats / Most Wanted Ghosts)
METHOD_FRIENDS_LIST      = 10
METHOD_REPORT_STATS      = 12   # match-end stats upload; HUGE payload from host (~1300B)
METHOD_END_GAME          = 15   # match-end lifecycle (MultiServer3 label)
METHOD_LEAVE_GATHERING   = 16   # "I am leaving" — fired by hosts AND guests
METHOD_LEADERBOARD_GLOBAL = 17  # global view of a leaderboard
METHOD_CLOSE_PARTICIPATION = 19 # host locks the lobby — fires at match-start AND match-end
METHOD_SEARCH_GATHERINGS = 20
METHOD_QUICK_MATCH       = 21
METHOD_INVITATIONS_LIST  = 22
METHOD_OPEN_PARTICIPATION = 23  # pair of m=19; opens lobby back up
METHOD_LIFECYCLE_26      = 26   # fires after m=19 at match-start; server no-ops it

# Quazal RendezVous::SessionVoid — "the gathering you tried to join is gone".
# Triggers PS3's "match no longer available" UI rather than a generic error.
ERR_SESSION_VOID = 0x80060019

# NAT traversal protocol (proto=3). The server pushes m=2 InitiateProbe to the
# host on JoinGathering, one call per joiner URL. The probe payload is a single
# qString (the joiner's station URL). This opens the host's NAT mapping toward
# the joiner; all in-lobby state changes (loadout, ready) then ride the
# resulting P2P channel, not the server. See protocols/nat.py.
NAT_PROTO            = 3
NAT_INITIATE_PROBE_M = 2

# proto=60 stat category IDs. The category selects WHICH board / stat set is
# being read; "Global" vs "Personal" is not part of the category — it's a view
# determined by the method (m=17 Global / m=7 AroundSelf).
CATEGORY_NAMES = {
    101: "Player Stats",
    102: "Most Wanted Ghosts",
    201: "Campaign Cash",
    202: "Campaign: Library",
    203: "Campaign: Times Square",
    204: "Campaign: Museum",
    205: "Campaign: Graveyard",
    301: "Instant Cash",
    302: "Instant: Survival",
    303: "Instant: Containment",
    304: "Instant: Destruction",
    305: "Instant: Protection",
    306: "Instant: Thief",
    307: "Instant: Slime Dunk",
}


def _ok(call_id: int, method: int, body: bytes):
    return ResponseOK(proto=PROTO, method=method, call_id=call_id, ret=body)


def _category_label(cat_id: int) -> str:
    return CATEGORY_NAMES.get(cat_id, f"<unknown:{cat_id}>")


def _parse_m9_pids(params: bytes) -> list[int]:
    """Extract the PID list from an m=9 request.
    Single:  [u32 cat][u32 count=1][u32 pid][u32 0][u32 1]           (20B)
    Multi:   [u32 cat][u32 count=N][u32 pidA][u32 pidB]...[u32 0][u32 N]  (variable)
    """
    if len(params) < 8:
        return []
    count = int.from_bytes(params[4:8], "little")
    pids = []
    off = 8
    for _ in range(count):
        if off + 4 > len(params):
            break
        pids.append(int.from_bytes(params[off:off+4], "little"))
        off += 4
    return [p for p in pids if p != 0]


def user_stats(dispatcher, conn, request: Request):
    """proto=60 m=9. Full per-user stats blob.
    Request wire format:
      Single:  [u32 cat][u32 count=1][u32 pid][u32 0][u32 1]           (20B)
      Multi:   [u32 cat][u32 count=2][u32 pidA][u32 pidB][u32 0][u32 2]  (24B)
    At login/stats-screen the client sends count=1 (self only).
    At match-start the client sends count=2 (both participants) for ALL 9 cats."""
    p = request.params
    cat = int.from_bytes(p[0:4], "little") if len(p) >= 4 else 0
    pids = _parse_m9_pids(p)

    if cat == 101:
        body = _build_multi_player_stats(pids)
        careers = {pid: _get_career_vec0(pid)[5] for pid in pids}
        log.info("%s: user_stats (m=9, cat=101 Player Stats, pids=%s) "
                 "— sending %d-entry reply (%dB; careers=%s)",
                 conn.remote, pids, len(pids), len(body),
                 {p: f"${c:.0f}" for p, c in careers.items()})
        return _ok(request.call_id, request.method, body)

    if cat == 102:
        # Power-ups + special_01..16 MWG-unlock counters: the stored career vec0
        # in the cat102 (-56) frame. Store-and-serve, per-PID.
        out = bytearray()
        rt.w_u32(out, len(pids))
        for pid in pids:
            _write_sparkstats_entry(out, pid, vec1=_career_v1_cat102(pid), txn=0)
        log.info("%s: user_stats (m=9, cat=102 power-ups/specials, pids=%s) — %dB",
                 conn.remote, pids, len(out))
        return _ok(request.call_id, request.method, bytes(out))

    if cat >= 201:
        # Leaderboard OWN-BASELINE — serve each player's stored best for THIS board
        # so the client knows its existing high score before pre-aggregating the
        # match. The client reads cash vec1[5] + mode-stat vec1[6] + map vec1[7] as
        # the pre-max baseline and CARRIES them into its next upload. The map MUST
        # be served here too: otherwise the client carries cash+stat (which we
        # feed) but map=0 (which we don't), and that carried 0 clobbers the real
        # map of any mode not played this match.
        out = bytearray()
        rt.w_u32(out, len(pids))
        for pid in pids:
            lb = _get_leaderboard(pid, cat)
            _write_sparkstats_entry(
                out, pid,
                vec1={5: lb.get("cash", 0.0), 6: lb.get("mode_stat", 0.0),
                      7: float(lb.get("map_id", 0))},
                txn=0)
        log.info("%s: user_stats (m=9, cat=%d=%r LB baseline, pids=%s) — %dB",
                 conn.remote, cat, _category_label(cat), pids, len(out))
        return _ok(request.call_id, request.method, bytes(out))

    # All other categories must return multi-PID entries (not empty).
    # Returning count=0 at match-start causes the client to clear its
    # cache, breaking wrap-up career cash even though cat=101 is correct.
    out = bytearray()
    rt.w_u32(out, len(pids))
    for pid in pids:
        _write_sparkstats_entry(out, pid, txn=0)
    log.info("%s: user_stats (m=9, cat=%d=%r, pids=%s) — returning %d zero entries (%dB)",
             conn.remote, cat, _category_label(cat), pids, len(pids), len(out))
    return _ok(request.call_id, request.method, bytes(out))


# SparkStats vector sizes. The m=9 reply uses the SAME qList wire format as the
# m=12 upload, so the per-entry shape must match: u32 pid + qString name +
# u32 h2 + vec<u32>×3.
_VEC0_LEN = 122
_VEC1_LEN = 96   # Must cover every slot the client reads. High-index stats
                 # (top_earner around vec1[63/64], max_location, level-completes)
                 # sit well past 31, and a short vec1 makes the client read past
                 # the buffer into garbage. 96 covers every live slot.
_VEC2_LEN = 0


# === STAT PERSISTENCE — the DB is the SINGLE SOURCE OF TRUTH ===============
# There is NO in-memory authoritative cache of career/leaderboard stats. m=12
# writes the DB; m=9 reads it back and serves exactly what is stored. So
# "served == persisted" is an invariant: a player can never see stats appear to
# update that weren't actually saved — if a write fails the next m=9 reads the
# old row and the failure surfaces in-session, instead of being masked by a
# cache and only revealed (as a backwards snap) on the next restart.
#
# The server is single-threaded asyncio, so one shared autocommit connection is
# safe and avoids per-request open/close churn. See db/career.py.
_DB = None


def _db_con():
    """Lazily-opened shared DB connection for the game protocol."""
    global _DB
    if _DB is None:
        _DB = db.open_db()
    return _DB

# Served to a player who has never uploaded: stats_version tag, everything else 0.
_DEFAULT_CAREER_VEC0 = [0.0] * career.VEC0_LEN
_DEFAULT_CAREER_VEC0[0] = 1002.0   # stats_version

# m=12 vec1 instant mode-block index -> leaderboard category. Block order is JOB
# order (Containment=0, Survival=1, Destruction=2, SlimeDunk=3, Protection=4,
# Thief=5); the cat numbering does NOT follow that order, so map explicitly.
_INSTANT_BLOCK_CAT = {0: 303, 1: 302, 2: 304, 3: 307, 4: 305, 5: 306}

# AroundSelf ("Personal" filter) window shape. The server controls WHICH rows
# the window contains, but not where the client places its highlight cursor —
# this client lands the cursor on the first non-self row regardless. So the
# window is shaped purely for visual parity: place the requester ~4th from the
# top, with a little context above and up to TRAIL rows below.
_AROUNDSELF_LEAD = 3    # rows ABOVE the requester (player lands ~4th)
_AROUNDSELF_TRAIL = 10  # max rows BELOW the requester


def _get_career_vec0(pid: int) -> list[float]:
    """Authoritative read of a player's career vec0 from the DB, or a fresh
    default if they've never uploaded. A read error degrades to the default
    (logged) rather than crashing the reply."""
    try:
        v = career.get_career(_db_con(), pid)
    except Exception:
        log.exception("persistence: career read failed for pid=%d", pid)
        v = None
    return v if v is not None else list(_DEFAULT_CAREER_VEC0)


def _get_leaderboard(pid: int, cat: int) -> dict:
    """Authoritative read of a player's leaderboard baseline for a board, or {}."""
    try:
        return career.get_leaderboard(_db_con(), pid, cat) or {}
    except Exception:
        log.exception("persistence: leaderboard read failed pid=%d cat=%d", pid, cat)
        return {}


def _compute_leaderboard_rows(vec0: list[float], vec1: list[float] | None
                              ) -> list[tuple[int, float, float, int]]:
    """Derive this match's per-category leaderboard rows from the vec1 mode-blocks.
    Instant uploads (vec1 len 31) carry all 6 mode-blocks; campaign uploads
    (len 15) carry campaign cash. Returns [(category, cash, mode_stat, map_id)]."""
    rows: list[tuple[int, float, float, int]] = []
    cash5 = vec0[5] if len(vec0) > 5 else 0.0
    if vec1 and len(vec1) >= 31:
        for b, catn in _INSTANT_BLOCK_CAT.items():
            base = 7 + 4 * b
            rows.append((catn, vec1[base], vec1[base + 1], int(vec1[base + 2])))
        rows.append((301, cash5, 0.0, 0))       # Instant Cash board ranks by cash
    elif vec1 and len(vec1) >= 15:
        rows.append((201, vec1[5], 0.0, 0))      # Campaign Cash board
    return rows


def _persist_match(pid: int, vec0: list[float],
                   lb_rows: list[tuple[int, float, float, int]]) -> bool:
    """Write one match's career + leaderboard state to the DB in a single
    transaction. Returns True on success, False on failure (logged at ERROR).
    The caller still ACKs the m=12; a failure surfaces on the next m=9 read
    (which returns the un-updated row), never masked by a cache."""
    try:
        con = _db_con()
        con.execute("BEGIN")
        try:
            career.upsert_career(con, pid, vec0)
            for catn, cash, stat, mp in lb_rows:
                career.upsert_leaderboard(con, pid, catn, cash, stat, mp)
            con.execute("COMMIT")
            return True
        except Exception:
            con.execute("ROLLBACK")
            raise
    except Exception:
        log.exception("persistence: WRITE FAILED for pid=%d — stats NOT saved", pid)
        return False


# Per-PID stats version / transaction id. Per the Quazal SDK docs the client
# enforces a strict-monotonic-increment rule for stats updates: cat=101
# (ReadStats) seeds the client's local stats_version at login; every
# subsequent NotificationEvent must carry a HIGHER txn id in param2 to be
# accepted, otherwise the broadcast is silently discarded. Populated lazily
# per PID and incremented on every m=12 receipt.
_STATS_TXN_ID: dict[int, int] = {}


def _parse_m12_sender_vec0(params: bytes, sender_pid: int) -> list[float] | None:
    """Walk the m=12 qList and return the sender's full vec0 (122 f32 slots) as
    a list, or None if not found / parse fails. Used to read multiple stat slots
    (cash vec0[5], ghosts trapped vec0[12], ...) from a single pass."""
    try:
        off = 0
        off += 4 + 4                                                     # gid, counter
        pcount = struct.unpack_from("<I", params, off)[0]; off += 4
        for _ in range(pcount):
            pid = struct.unpack_from("<I", params, off)[0]; off += 4
            nlen = struct.unpack_from("<H", params, off)[0]; off += 2 + nlen
            off += 4                                                     # h2
            v0c = struct.unpack_from("<I", params, off)[0]; off += 4
            v0 = list(struct.unpack_from("<%df" % v0c, params, off)); off += v0c * 4
            v1c = struct.unpack_from("<I", params, off)[0]; off += 4
            off += v1c * 4
            v2c = struct.unpack_from("<I", params, off)[0]; off += 4
            off += v2c * 4
            if pid == sender_pid:
                return v0
    except Exception as e:
        log.warning("_parse_m12_sender_vec0 failed: %s", e)
    return None


def _parse_m12_sender_vec1(params: bytes, sender_pid: int) -> list[float] | None:
    """Walk the m=12 qList and return the sender's full vec1 (31 f32 slots), or
    None if not found / parse fails. vec1 = 7 header slots + 6 mode-blocks x 4
    [cash, objective, map, stat] in job order (Containment=block0 base7,
    Survival=block1 base11, ...). The objective slot (block_base+1) is
    mode-specific: e.g. Containment vec1[8] is the literal GHOSTS-TRAPPED count
    for the match, and is 0 for non-Containment matches."""
    try:
        off = 0
        off += 4 + 4                                                     # gid, counter
        pcount = struct.unpack_from("<I", params, off)[0]; off += 4
        for _ in range(pcount):
            pid = struct.unpack_from("<I", params, off)[0]; off += 4
            nlen = struct.unpack_from("<H", params, off)[0]; off += 2 + nlen
            off += 4                                                     # h2
            v0c = struct.unpack_from("<I", params, off)[0]; off += 4
            off += v0c * 4
            v1c = struct.unpack_from("<I", params, off)[0]; off += 4
            v1 = list(struct.unpack_from("<%df" % v1c, params, off)); off += v1c * 4
            v2c = struct.unpack_from("<I", params, off)[0]; off += 4
            off += v2c * 4
            if pid == sender_pid:
                return v1
    except Exception as e:
        log.warning("_parse_m12_sender_vec1 failed: %s", e)
    return None


def _write_sparkstats_entry(out: bytearray, pid: int,
                            vec0: dict[int, float] | None = None,
                            vec1: dict[int, float] | None = None,
                            vec2: dict[int, float] | None = None,
                            txn: int = 0,
                            vec2_len: int = _VEC2_LEN,
                            name: str | None = None) -> None:
    """Append one SparkStats entry to `out`. Does NOT write the list count
    prefix — caller is responsible for that. vec0/vec1 are sparse slot→value
    dicts; unmentioned slots default to 0.0."""
    rt.w_u32(out, pid)
    rt.w_qstring(out, name or f"PID{pid}")
    rt.w_u32(out, txn)
    v0 = vec0 or {}
    v1 = vec1 or {}
    rt.w_u32(out, _VEC0_LEN)
    for i in range(_VEC0_LEN):
        out += struct.pack("<f", v0.get(i, 0.0))
    rt.w_u32(out, _VEC1_LEN)
    for i in range(_VEC1_LEN):
        out += struct.pack("<f", v1.get(i, 0.0))
    v2 = vec2 or {}
    rt.w_u32(out, vec2_len)
    for i in range(vec2_len):
        out += struct.pack("<f", v2.get(i, 0.0))


def _build_sparkstats_reply(pid: int, vec0_cash: float, vec1_cash: float,
                            txn: int) -> bytes:
    """Single-entry SparkStats qList. Used by m=12 reply path."""
    out = bytearray()
    rt.w_u32(out, 1)
    _write_sparkstats_entry(out, pid,
                            vec0={5: vec0_cash},
                            vec1={10: vec1_cash},
                            txn=txn)
    return bytes(out)


def _career_v1(pid: int) -> dict[int, float]:
    """cat=101 reply body: the stored career vec0 in the m=9 vec1 frame
    (vec1_slot = vec0_slot + 5). Carries career cash (vec0[5]->vec1[10]), Ghosts
    Trapped (vec0[12]->vec1[17]), MWG mask (vec0[14]->vec1[19]), top-earner masks
    (vec0[58/59]->vec1[63/64]), and everything else the client maintains."""
    v0 = _get_career_vec0(pid)
    return {i + 5: v0[i] for i in range(len(v0))}


def _career_v1_cat102(pid: int) -> dict[int, float]:
    """cat=102 reply body: the stored career vec0 in the cat102 frame
    (vec1_slot = vec0_slot - 56). objects_saved 61->5, powerups 62->6,
    which_powerups 63->7, special_01..16 64..79->8..23, slimer-kill counter
    80->24, captured2 (Polar/Glutton) 84->28."""
    v0 = _get_career_vec0(pid)
    g = lambda i: v0[i] if i < len(v0) else 0.0
    v1 = {5: g(61), 6: g(62), 7: g(63)}
    for n in range(16):              # special_01..16 -> vec1[8..23]
        v1[8 + n] = g(64 + n)
    v1[24] = g(80)                   # slimer-kill counter (Rotten)
    v1[28] = g(84)                   # mostwanted_ghost_captured2 (Polar/Glutton)
    return v1


def _build_multi_player_stats(pids: list[int]) -> bytes:
    """m=9 cat=101 reply: one entry per requested PID, each carrying that
    player's stored career vec0 (store-and-serve). h2=0 (stable txn for cat=101;
    the incrementing txn rides the proto=14 push instead)."""
    out = bytearray()
    rt.w_u32(out, len(pids))
    for pid in pids:
        _write_sparkstats_entry(out, pid, vec1=_career_v1(pid), txn=0)
    return bytes(out)


def leaderboard_query(dispatcher, conn, request: Request):
    """proto=60 leaderboard list query. Two methods, same wire shape:
      m=7  GetLeaderboardStatsAroundSelf — windowed list of `count` entries
            centered (or starting from `offset` relative) to the requester's
            global rank. Used by the UI's "Personal" filter button.
      m=17 GetLeaderboardStats          — top-N global list paged from rank 1
            (page = offset / count + 1). Used by the UI's "Global" filter.

    Params: [u32 category][u32 offset][u32 count] (12B). Categories are listed
    in CATEGORY_NAMES. The reply is the same SparkStats qList wire shape as m=9;
    the client decodes both with the same handler."""
    p = request.params
    cat = int.from_bytes(p[0:4], "little") if len(p) >= 4 else 0
    offset = int.from_bytes(p[4:8], "little") if len(p) >= 8 else 0
    count = int.from_bytes(p[8:12], "little") if len(p) >= 12 else 0
    view = "AroundSelf" if request.method == METHOD_LEADERBOARD_SELF else "Global"

    try:
        ranked = career.ranked_for_category(_db_con(), cat)
    except Exception:
        log.exception("leaderboard rank query failed cat=%d", cat)
        ranked = []
    page, start = _leaderboard_page(ranked, conn.user_pid, offset, count,
                                    around_self=(request.method == METHOD_LEADERBOARD_SELF))

    con = _db_con()
    out = bytearray()
    rt.w_u32(out, len(page))
    for j, row in enumerate(page):
        position = start + j + 1   # ABSOLUTE global # — a player on page 2 or inside
                                   # an AroundSelf window must show their true rank
                                   # (e.g. #51), not a page-relative 1..N.
        pid = row["pid"]
        player_name = accounts.name_for_pid(con, pid)
        mp_rank = _get_career_vec0(pid)[4]
        # Columns: vec1[0]=# (position), vec1[5]=Cash, vec1[6]=mode-stat,
        # vec1[7]=Map Played (map id; the client renders the map name),
        # vec0[19]=Rank (the player's own uploaded player_rank vec0[4]).
        _write_sparkstats_entry(out, pid,
                                vec0={19: mp_rank},
                                vec1={0: float(position), 5: row["cash"],
                                      6: row["mode_stat"], 7: float(row["map_id"])},
                                txn=position,
                                vec2_len=1,
                                name=player_name)

    log.info("%s: leaderboard %s (m=%d, cat=%d=%r, offset=%d, count=%d) "
             "— returning %d entries",
             conn.remote, view, request.method, cat, _category_label(cat),
             offset, count, len(page))
    return _ok(request.call_id, request.method, bytes(out))


def _leaderboard_page(ranked: list[dict], requester_pid: int,
                      offset: int, count: int,
                      around_self: bool) -> tuple[list[dict], int]:
    """Slice a page out of the cash-ranked rows (from career.ranked_for_category)
    and return (page, start_index) — start_index is the absolute rank offset of
    the first returned row, so the caller can number entries #start+1, #start+2…
    AroundSelf (m=7) centers the window on the requester's row; Global (m=17)
    starts at `offset`."""
    if not ranked:
        return [], 0
    if around_self:
        # AroundSelf: the SERVER positions the window — the player ~4th from the top
        # (LEAD rows above for context) and up to TRAIL rows below. We never exceed
        # the client-requested `count`. The highlight cursor is the client's own
        # (lands on first non-self) — we only shape the window for visual parity.
        idx = next((i for i, r in enumerate(ranked) if r["pid"] == requester_pid), 0)
        start = max(0, idx - _AROUNDSELF_LEAD)
        end = idx + 1 + _AROUNDSELF_TRAIL
        return ranked[start:end][:count], start
    start = offset
    return ranked[start:start + count], start


def _parse_filter_params(blob: bytes):
    """Decode a SearchGatherings filter blob. Wire structure:
    [qstring F0=Ranked][u32 N=7][7× qstring slot][qstring F_post=GameMode]
    [u32 T1=0][u32 T2=maxResults]. Each filter qstring is "" = Any,
    "<digit>" = a specific value to match.

    Returns a dict of non-empty filters, or None if the blob is too short /
    malformed to parse (in which case the caller falls back to no filter)."""
    try:
        i = 0
        def _qstr():
            nonlocal i
            ln = int.from_bytes(blob[i:i+2], "little")
            s = blob[i+2:i+2+ln].rstrip(b"\x00").decode("latin1")
            i += 2 + ln
            return s
        def _u32():
            nonlocal i
            v = int.from_bytes(blob[i:i+4], "little")
            i += 4
            return v
        f0 = _qstr()
        n = _u32()
        if n != 7:
            return None
        slots = [_qstr() for _ in range(7)]
        f_post = _qstr()
        # Trailer u32s are ignored — maxResults isn't currently enforced.
        return {
            "ranked":     f0,        # "" / "1" / "0"
            "level_id":   slots[0],  # numeric string ("1".."4" Campaign, "12".."44" Instant)
            "job_id":     slots[1],  # numeric string "1".."6"
            "difficulty": slots[2],  # numeric string "1".."3"
            "game_mode":  f_post,    # "" / "1" Campaign / "2" Instant
            # slots[3] is always "" and slots[4..6] are always "1" — ignored
        }
    except Exception:
        return None


# Settings field offsets, relative to the start of the 64-byte settings block.
_SET_RANKED   = 0x00   # u8
_SET_GAMEMODE = 0x01   # u8 (1=Campaign, 2=Instant)
_SET_LEVEL_ID = 0x21   # u32 LE
_SET_JOB_ID   = 0x25   # u32 LE
_SET_DIFFCLTY = 0x29   # u8


def _gathering_settings(g):
    """Return the gathering's 64-byte settings tail or None if raw_params
    is too short / malformed."""
    rp = g.raw_params
    DISPLAY_OFF = 0x34
    if len(rp) < DISPLAY_OFF + 2:
        return None
    dlen = int.from_bytes(rp[DISPLAY_OFF:DISPLAY_OFF + 2], "little")
    start = DISPLAY_OFF + 2 + dlen
    end = start + 0x40
    if len(rp) < end:
        return None
    return rp[start:end]


def _gathering_matches_filter(g, f) -> bool:
    """Match one gathering's settings against a parsed filter dict. Empty
    filter values pass through (= "Any"). Returns False only on an explicit
    mismatch; missing/unreadable settings pass through too (fail open)."""
    s = _gathering_settings(g)
    if s is None:
        return True

    def _u32(off):
        return int.from_bytes(s[off:off+4], "little")

    if f["ranked"]:
        want = 1 if f["ranked"] == "1" else 0
        if s[_SET_RANKED] != want:
            return False
    if f["game_mode"]:
        want = int(f["game_mode"])      # "1" or "2"
        if s[_SET_GAMEMODE] != want:
            return False
    if f["level_id"]:
        want = int(f["level_id"])
        if _u32(_SET_LEVEL_ID) != want:
            return False
    if f["job_id"]:
        want = int(f["job_id"])
        if _u32(_SET_JOB_ID) != want:
            return False
    if f["difficulty"]:
        want = int(f["difficulty"])
        if s[_SET_DIFFCLTY] != want:
            return False
    return True


def search_gatherings(dispatcher, conn, request: Request):
    """proto=60 m=20. Returns the list of active gatherings, optionally
    filtered by the request's filter blob (see _parse_filter_params).
    Wire shape: [u32 count][gathering struct]*count.
    Each struct is the raw SparkGame blob the host sent in CreateGathering,
    with our assigned gathering_id + owner_pid overlaid (see
    state.gatherings.Gathering.render_settings_for_browse)."""
    active = gatherings.all_gatherings()

    # Hide matches with no public slots left (invite-only or fully booked)
    # and matches whose host called CloseParticipation (lobby locked at
    # countdown-start).
    before = len(active)
    active = [g for g in active
              if g.public_remaining() > 0 and not g.closed]
    hidden = before - len(active)
    if hidden:
        log.info("%s: SearchGatherings hid %d match(es) (no slots or closed)",
                 conn.remote, hidden)

    f = _parse_filter_params(request.params) if request.params else None
    if request.params and f is None:
        log.info("%s: SearchGatherings filter PARSE FAILED (%dB blob) — "
                 "fail-open, returning all", conn.remote, len(request.params))
    elif f and any(f.values()):
        filtered = [g for g in active if _gathering_matches_filter(g, f)]
        log.info("%s: SearchGatherings filter %s — %d/%d gatherings pass",
                 conn.remote, f, len(filtered), len(active))
        active = filtered
    elif f is not None:
        log.info("%s: SearchGatherings filter all-Any %s — returning all %d",
                 conn.remote, f, len(active))

    # Two-section response:
    #   [u32 count]
    #   [gathering struct with 63-byte truncated settings tail]*count
    #   [u32 url_group_count]   ← same as count
    #   [u32 gid][u32 url_count][qstring url]*url_count   per gathering
    out = bytearray()
    rt.w_u32(out, len(active))
    for g in active:
        out += g.render_settings_for_browse()
    rt.w_u32(out, len(active))
    for g in active:
        out += g.render_url_group_for_browse()

    log.info("%s: SearchGatherings — returning %d gathering(s) (%dB)",
             conn.remote, len(active), len(out))
    log.info("%s: SearchGatherings raw filter params: %s",
             conn.remote, request.params.hex())
    return _ok(request.call_id, METHOD_SEARCH_GATHERINGS, bytes(out))


def create_gathering(dispatcher, conn, request: Request):
    """proto=60 m=4. The PS3 sends the full SparkGame Gathering struct in the
    params; we store the raw bytes and assign gathering_id + owner_pid. The
    response is just the 4-byte assigned gathering_id."""
    g = gatherings.create(owner_pid=conn.user_pid, owner_remote=conn.remote,
                          raw_params=request.params, host_conn=conn)
    log.info("%s: CreateGathering(pid=%d, %dB params) → id=%d (host=%r)",
             conn.remote, conn.user_pid, len(request.params), g.id,
             g.host_display_name())
    log.info("%s: CreateGathering raw params: %s",
             conn.remote, request.params.hex())
    out = bytearray()
    rt.w_u32(out, g.id)
    return _ok(request.call_id, METHOD_CREATE_GATHERING, bytes(out))


def join_gathering(dispatcher, conn, request: Request):
    """proto=60 m=5. Request shape (6B): `[u32 gid][u8][u8]`. The two trailing
    bytes are slot / loadout hints and aren't needed to build the response.

    Response has three sections:
      1. `list<qString>` of the host's station URLs — pulled live from the
         host's RegisterEx-stashed `conn.station_urls`. PS3 uses these to start
         hole-punching the host without waiting for a proto=3 m=2 push.
      2. Participant block: `[u32 count]` then per-participant
         `[u32 pid][qString name][16B state]` for everyone in the lobby
         *except* the requesting joiner.
      3. Embedded gathering struct (see `Gathering.render_join_embed`) with
         participant_count flipped to the post-join total.

    Unknown gid → `0x80060019` (RendezVous::SessionVoid), the standard error
    for "the gathering you picked is gone." Triggers PS3's
    'match no longer available' UI instead of a generic failure popup —
    relevant because the lobby browser has a manual refresh button so a
    user can absolutely click Join on a stale entry.
    """
    if len(request.params) < 4:
        log.warning("%s: JoinGathering: params too short (%dB)",
                    conn.remote, len(request.params))
        return ResponseError(proto=PROTO, call_id=request.call_id,
                             error_code=ERR_SESSION_VOID)

    gid = struct.unpack_from("<I", request.params, 0)[0]
    g = gatherings.get(gid)
    if g is None:
        log.info("%s: JoinGathering(id=%d, pid=%d) — SessionVoid (gathering gone)",
                 conn.remote, gid, conn.user_pid)
        return ResponseError(proto=PROTO, call_id=request.call_id,
                             error_code=ERR_SESSION_VOID)

    host_conn = g.host_conn
    if host_conn is None or not getattr(host_conn, "station_urls", ()):
        # Host left the secure connection without explicit DestroyGathering and
        # the GC reaper hasn't fired yet — treat as void.
        log.warning("%s: JoinGathering(id=%d) — host_conn missing/empty station_urls",
                    conn.remote, gid)
        return ResponseError(proto=PROTO, call_id=request.call_id,
                             error_code=ERR_SESSION_VOID)

    # Slot validation. Handles the stale-browse-list race: the match showed up
    # in the user's browse list when it had a public slot, then somebody else
    # took it before this user clicked Join.
    #   - Game-hard-cap: never let participants exceed MAX (4).
    #   - Invited joiner: any slot kind is fine — they're filling a private.
    #   - Uninvited joiner: requires a public slot.
    is_invited = conn.user_pid in g.invited_pids
    if g.is_full() or (not is_invited and g.public_remaining() <= 0):
        log.info("%s: JoinGathering(id=%d, pid=%d) — SessionVoid (full or "
                 "no public slot; invited=%s, public_remaining=%d, count=%d)",
                 conn.remote, gid, conn.user_pid, is_invited,
                 g.public_remaining(), len(g.participants))
        return ResponseError(proto=PROTO, call_id=request.call_id,
                             error_code=ERR_SESSION_VOID)

    # Track the joiner. Display name: the conn doesn't carry a username for
    # non-host users (Login has it, but it isn't stashed on the conn), so use a
    # pid-based placeholder.
    joiner_name = f"pid_{conn.user_pid}"
    gatherings.add_participant(g.id, conn.user_pid, joiner_name, conn.remote,
                               conn=conn)

    out = bytearray()
    # Section 1: host's station URLs (LAN + WAN typically).
    rt.w_u32(out, len(host_conn.station_urls))
    for url in host_conn.station_urls:
        rt.w_qstring(out, url)

    # Section 2: existing participants (everyone except the requesting joiner).
    existing = [p for p in g.participants if p.pid != conn.user_pid]
    rt.w_u32(out, len(existing))
    for p in existing:
        rt.w_u32(out, p.pid)
        rt.w_qstring(out, p.display_name)
        out += p.state  # 16-byte zero trailer until UpdateParticipantInfo arrives

    # Section 3: embedded gathering struct with post-join count.
    out += g.render_join_embed(post_join_count=len(g.participants))

    log.info("%s: JoinGathering(id=%d, pid=%d) — %d participant(s) now (%dB response)",
             conn.remote, gid, conn.user_pid, len(g.participants), len(out))

    # NAT-traversal hole-punch: push proto=3 m=2 to host with each of the
    # joiner's station URLs. This opens A's NAT mapping so B's P2P packets
    # can flow. Required for P2P state to work, but does NOT update the
    # lobby UI — that's the notification push below.
    joiner_urls = getattr(conn, "station_urls", ()) or ()
    if not joiner_urls:
        log.warning("%s: JoinGathering(id=%d) — joiner has no station_urls; "
                    "P2P won't establish.", conn.remote, gid)
    for url in joiner_urls:
        probe = bytearray()
        rt.w_qstring(probe, url)
        dispatcher.send_request(host_conn, NAT_PROTO, NAT_INITIATE_PROBE_M, bytes(probe))

    # Push proto=14 NotificationEvent(type=900002) to every existing participant
    # so the joiner appears in their lobby UI. The NAT punch above is necessary
    # but not sufficient: the client only adds the joiner to its lobby roster
    # (and fires the "participant list changed" UI callback) when it receives
    # this matchmaking-level event. See notification.py.
    notification.push_join(dispatcher, g, joiner_pid=conn.user_pid)
    # The joiner's own lobby UI also needs every participant, INCLUDING itself.
    # The host's CreateGathering handler inserts the host into its own roster,
    # but the guest's JoinGathering handler has no equivalent local-insert path,
    # so the server pushes one ParticipantProcessed per participant to the
    # joiner (self + existing).
    notification.push_participants_to_joiner(
        dispatcher, g, joiner_pid=conn.user_pid)

    return _ok(request.call_id, METHOD_JOIN_GATHERING, bytes(out))


def leave_gathering_game(dispatcher, conn, request: Request):
    """proto=60 m=16: caller leaves the gathering. Fired by both hosts and
    guests on lobby exit — guests fire it alone, hosts fire it *after*
    `proto=21 m=36 DestroyGathering` (the host's own departure is bookkeeping
    that runs after the gathering itself is gone). Always remove-only on this
    side; destruction is m=36's job."""
    if len(request.params) >= 4:
        gid = struct.unpack_from("<I", request.params, 0)[0]
    else:
        gid = 0
    g = gatherings.get(gid)
    if g is None:
        log.info("%s: LeaveGathering(id=%d) — no-op (gathering already gone)",
                 conn.remote, gid)
    else:
        removed = gatherings.remove_participant(gid, conn.user_pid)
        log.info("%s: LeaveGathering(id=%d, pid=%d) — %s; %d participant(s) remain",
                 conn.remote, gid, conn.user_pid,
                 "removed" if removed else "wasn't in participant list",
                 len(g.participants))
        if removed:
            # Notify remaining participants so their lobby UIs update.
            # Skipped when `removed` is False — `wasn't in participant list`
            # means the leaver had already been pruned (e.g. by disconnect),
            # so there's no new state to announce.
            notification.push_leave(dispatcher, g, leaver_pid=conn.user_pid)
    return _ok(request.call_id, METHOD_LEAVE_GATHERING, b"")


def quick_match(dispatcher, conn, request: Request):
    """proto=60 m=21 QuickMatchWithHostUrls. Request shape (17B):
      [u8 ranked][u32 ?=3][u32 ?=50][u32 ?=0][u32 ?=20]
    Only the ranked flag is honored. The trailing u32s are hint params
    (game_mode_any / max_ping / offset / max_results) and are ignored.

    Quick Match button → ranked=1; Unranked Match → ranked=0.

    Response: the SAME two-section wire shape as m=20 SearchGatherings (the
    method name QuickMatchWithHostUrls parallels BrowseMatchesWithHostUrls
    deliberately). The server picks the first matching open gathering and
    returns it as a one-element match list; the client then fires its normal
    m=5 JoinGathering for the embedded gid. An empty list makes the client show
    the "no match available" UI. A bare [u32 gid] reply does NOT work — the
    client ignores it and never fires m=5.
    """
    ranked = request.params[0] if request.params else 1
    log.info("%s: QuickMatch(ranked=%d) params=%s",
             conn.remote, ranked, request.params.hex())

    chosen = None
    candidates = 0
    for g in gatherings.all_gatherings():
        if g.owner_pid == conn.user_pid:
            continue
        if g.host_conn is None or not getattr(g.host_conn, "station_urls", ()):
            continue
        # Slot enforcement: quick-match only places non-invited joiners, so
        # require a public slot. Invite-only matches (public=0) are unreachable
        # via quick-match by design.
        if g.public_remaining() <= 0:
            continue
        # Host locked the lobby (countdown started / match ended) — match is
        # no longer joinable. Skip.
        if g.closed:
            continue
        s = _gathering_settings(g)
        if s is not None and s[_SET_RANKED] != ranked:
            continue
        candidates += 1
        if chosen is None:
            chosen = g

    log.info("%s: QuickMatch(ranked=%d) — %d candidate(s), returning gid=%d",
             conn.remote, ranked, candidates, chosen.id if chosen else 0)

    # Two-section wire shape (same as SearchGatherings):
    #   [u32 gathering_count][gathering struct]*count
    #   [u32 url_group_count][gid+url_count+URLs]*count
    out = bytearray()
    rt.w_u32(out, 1 if chosen else 0)
    if chosen:
        out += chosen.render_settings_for_browse()
    rt.w_u32(out, 1 if chosen else 0)
    if chosen:
        out += chosen.render_url_group_for_browse()
    return _ok(request.call_id, METHOD_QUICK_MATCH, bytes(out))


_SOCIAL_LABELS = {METHOD_FRIENDS_LIST: "friends_list",
                  METHOD_INVITATIONS_LIST: "invitations_list"}


def social_list(dispatcher, conn, request: Request):
    """proto=60 m=10 (Friends) and m=22 (Invitations). Both fire when the user
    opens those menus. The client accepts an empty success and shows an empty
    list; the server does not implement friends/invitations, so it returns that.
    The populated-list wire shape would need to be defined to support them."""
    label = _SOCIAL_LABELS.get(request.method, f"social_m{request.method}")
    log.info("%s: %s (m=%d) params(%dB)=%s — STUB empty-success",
             conn.remote, label, request.method, len(request.params), request.params.hex())
    return _ok(request.call_id, request.method, b"")


# Match-lifecycle methods the host fires between match-start and match-end.
# The server returns empty-OK to each so the client advances through its
# match phases normally; only m=12 ReportStats carries data the server acts on.
_LIFECYCLE_LABELS = {
    METHOD_END_GAME:           "EndGame",
    METHOD_CLOSE_PARTICIPATION: "CloseParticipation",
    METHOD_OPEN_PARTICIPATION:  "OpenParticipation",
    METHOD_LIFECYCLE_26:       "Lifecycle_m26",
    METHOD_REPORT_STATS:       "ReportStats",
}


def lifecycle_stub(dispatcher, conn, request: Request):
    """Lifecycle methods (m=12/15/26).
    m=12 ReportStats: persist the uploaded career vec0 to the DB, then reply
    with a SparkStats blob carrying the BASELINE (pre-match cash) at vec0[5] and
    the TOTAL (post-match career cash) at vec1[10], plus h2=txn_id. The wrap-up
    screen reads these two values to animate Career Cash from baseline to total,
    so this reply drives that animation; it is not a passive ack.

    A per-match proto=14 type=901001 stats-processed notification is also fired,
    but only once all participants have reported (see the batch helpers below),
    so it is armed here rather than pushed directly.

    m=15 EndGame is handled separately below; m=26 and any other lifecycle
    method get an empty-OK."""
    label = _LIFECYCLE_LABELS.get(request.method, f"m{request.method}")
    if request.method == METHOD_REPORT_STATS and request.params:
        # === STORE-AND-SERVE PERSISTENCE ==================================
        # The client uploads its FULL career vec0 with everything already
        # aggregated (cash vec0[5], Ghosts Trapped vec0[12], MWG masks vec0[14]/
        # [84], top-earner masks vec0[58/59], specials, money, job/level counts,
        # level_complete, power-ups). We snapshot it verbatim, keyed by PID, and
        # serve it straight back as the m=9 baseline — no server-side math.
        # See db/career.py.
        sender_vec0 = _parse_m12_sender_vec0(request.params, conn.user_pid)
        sender_vec1 = _parse_m12_sender_vec1(request.params, conn.user_pid)
        pid = conn.user_pid
        # Baseline = pre-match career cash, read from the DB BEFORE we overwrite
        # it (drives the wrap-up animation's starting value).
        prior = _get_career_vec0(pid)[5]
        if sender_vec0:
            lb_rows = _compute_leaderboard_rows(sender_vec0, sender_vec1)
            saved = _persist_match(pid, sender_vec0, lb_rows)
            if not saved:
                log.error("%s: m=12 pid=%d — DB write FAILED; served stats will "
                          "NOT reflect this match (surfaces on next stats query)",
                          conn.remote, pid)
            new_total = sender_vec0[5] if len(sender_vec0) > 5 else prior
        else:
            log.warning("%s: m=12 from pid=%d — could not parse sender vec0; "
                        "nothing persisted", conn.remote, pid)
            new_total = prior
        _STATS_TXN_ID[pid] = _STATS_TXN_ID.get(pid, 0) + 1
        new_txn = _STATS_TXN_ID[pid]
        # Log values derived straight from the upload (in hand) — no caches.
        v0 = sender_vec0 or []
        g = lambda i: v0[i] if i < len(v0) else 0.0
        te_job = int(g(59))
        log.info("%s: %s (m=%d, %dB) — pid=%d career $%.0f -> $%.0f, "
                 "trapped=%.0f MWG=0x%x cap2=0x%x top_earner job=0x%x(pc=%d) "
                 "camp=0x%x, txn -> %d",
                 conn.remote, label, request.method, len(request.params),
                 pid, prior, new_total,
                 g(12), int(g(14)), int(g(84)),
                 te_job, bin(te_job).count("1"), int(g(58)),
                 new_txn)
        # Track m=12 reports: wait for ALL participants in the locked roster to
        # report, THEN fire proto=14 stats_processed to every participant at
        # once (self-only payload per recipient), so all players' stats update
        # together. A 30s timeout fires the batch anyway if a player never
        # reports.
        sender_gathering = next(
            (g for g in gatherings.all_gatherings()
             if any(p.pid == conn.user_pid for p in g.participants)),
            None,
        )
        if sender_gathering is None:
            log.warning("%s: m=12 from pid=%d — no gathering contains them; "
                        "skipping stats-processed notification",
                        conn.remote, conn.user_pid)
        else:
            # Fallback: if CloseParticipation snapshot didn't run for some
            # reason (e.g. handler order), seed expected from current roster.
            if not sender_gathering.expected_m12_pids:
                sender_gathering.expected_m12_pids = {p.pid for p in sender_gathering.participants}
                sender_gathering.received_m12_pids = set()
                log.info("%s: m=12 batch seed gid=%d (no prior CloseParticipation snapshot) "
                         "— expecting %s", conn.remote, sender_gathering.id,
                         sorted(sender_gathering.expected_m12_pids))
            sender_gathering.received_m12_pids.add(conn.user_pid)
            if sender_gathering.received_m12_pids >= sender_gathering.expected_m12_pids:
                _fire_stats_processed_batch(dispatcher, sender_gathering,
                                            reason="all-reported")
            else:
                waiting = sender_gathering.expected_m12_pids - sender_gathering.received_m12_pids
                log.info("%s: m=12 from pid=%d (gid=%d) — reported=%s waiting=%s",
                         conn.remote, conn.user_pid, sender_gathering.id,
                         sorted(sender_gathering.received_m12_pids), sorted(waiting))
                # Arm the safety timeout on the first m=12 of this batch
                if sender_gathering.m12_timeout_handle is None:
                    try:
                        import asyncio as _asyncio
                        loop = _asyncio.get_running_loop()
                        sender_gathering.m12_timeout_handle = loop.call_later(
                            M12_BATCH_TIMEOUT_SECONDS,
                            _on_m12_timeout, dispatcher, sender_gathering.id,
                        )
                    except RuntimeError:
                        # No running loop (e.g. unit tests) — skip timeout
                        log.info("no running loop; m=12 batch timeout not armed for gid=%d",
                                 sender_gathering.id)
        # m=12 reply: SparkStats with BASELINE at vec0[5] and TOTAL at vec1[10].
        # Wrap-up screen reads these to animate cash from baseline → total. total
        # = this match's uploaded career cash (new_total); the wrap-up animates off
        # the values the client already has, so it's shown even if the DB write
        # failed (the failure then surfaces on the next stats query, not here).
        total_cash = new_total
        body = _build_sparkstats_reply(
            pid=conn.user_pid,
            vec0_cash=prior,                          # baseline = pre-match career
            vec1_cash=total_cash,                     # total = post-match career
            txn=new_txn,
        )
        log.info("%s: m=12 reply (%dB): pid=%d baseline=$%.0f total=$%.0f txn=%d",
                 conn.remote, len(body), conn.user_pid, prior,
                 total_cash, new_txn)
        return _ok(request.call_id, request.method, body)
    if request.method == METHOD_END_GAME:
        # EndGame (m=15) = UNRANKED match end, mutually exclusive with the ranked
        # ReportStats/m=12 teardown: unranked matches report no stats. So the
        # m=12 batch armed at CloseParticipation will never complete. The FIRST
        # EndGame for the gathering cancels that wait;
        # every later EndGame (the other peers) finds it already clear → ignored.
        gid = int.from_bytes(request.params[:4], "little") if len(request.params) >= 4 else 0
        g = gatherings.get(gid) if gid else None
        if g is None:
            matches = gatherings.find_gatherings_containing_pid(conn.user_pid)
            g = matches[0] if matches else None
        if g is not None and (g.m12_timeout_handle is not None or g.expected_m12_pids):
            _cancel_m12_batch(g, reason="EndGame (unranked teardown)")
            log.info("%s: EndGame (m=%d) gid=%d — cancelled pending m=12 batch wait",
                     conn.remote, request.method, g.id)
        else:
            log.info("%s: EndGame (m=%d) gid=%d — no pending m=12 wait, ignored",
                     conn.remote, request.method, gid)
        return _ok(request.call_id, request.method, b"")
    log.info("%s: %s (m=%d) params(%dB)=%s — empty-OK",
             conn.remote, label, request.method,
             len(request.params), request.params.hex())
    return _ok(request.call_id, request.method, b"")


def close_participation(dispatcher, conn, request: Request):
    """proto=60 m=19. Host locks the lobby — fires at countdown-start and
    again at match-end. Mark the gathering closed so SearchGatherings (m=20)
    and QuickMatch (m=21) hide it from new joiners. Returns empty-OK.
    Params: `[u32 gathering_id]` (4B, little-endian; e.g. `10270000` = gid 10000).

    Also snapshot the participant set as the expected m=12 reporters for the
    end-of-match stats push. The first CloseParticipation (lobby-lock at
    countdown-start) is when the roster is final; subsequent calls are no-ops
    for the snapshot."""
    gid = int.from_bytes(request.params[:4], "little") if len(request.params) >= 4 else 0
    changed = gatherings.set_closed(gid, True) if gid else False
    g = gatherings.get(gid) if gid else None
    if g is not None and not g.expected_m12_pids:
        g.expected_m12_pids = {p.pid for p in g.participants}
        g.received_m12_pids = set()
        log.info("%s: CloseParticipation snapshot gid=%d — expecting m=12 from %s",
                 conn.remote, gid, sorted(g.expected_m12_pids))
    log.info("%s: CloseParticipation (m=19) gid=%d params(%dB)=%s — %s",
             conn.remote, gid, len(request.params), request.params.hex(),
             "closed" if changed else "no-op (already closed or unknown gid)")
    return _ok(request.call_id, METHOD_CLOSE_PARTICIPATION, b"")


# ---- End-of-match m=12 broadcast helpers ----

M12_BATCH_TIMEOUT_SECONDS = 30.0

def _fire_stats_processed_batch(dispatcher, gathering, reason: str) -> None:
    """Fire proto=14 stats_processed to every participant of the gathering,
    self-only data per recipient. Clear the m=12 tracking state.

    `reason` is "all-reported" or "timeout"; logged for diagnostics.
    """
    if gathering.m12_timeout_handle is not None:
        try:
            gathering.m12_timeout_handle.cancel()
        except Exception:
            pass
        gathering.m12_timeout_handle = None

    if not gathering.received_m12_pids:
        log.info("stats batch fire skipped (gid=%d): no m=12 reports received",
                 gathering.id)
        return

    missing = gathering.expected_m12_pids - gathering.received_m12_pids
    log.info("firing stats_processed batch gid=%d reason=%s reported=%s missing=%s",
             gathering.id, reason,
             sorted(gathering.received_m12_pids), sorted(missing))
    # Use ANY reported pid as the "source" for routing metadata. The
    # notification dispatcher only treats source as informational.
    source_pid = next(iter(gathering.received_m12_pids))
    # Per-recipient career cash, read from the DB (source of truth) for everyone
    # in the gathering — the notification embeds each player's own value.
    career_cash = {p.pid: career.career_cash(_db_con(), p.pid)
                   for p in gathering.participants}
    notification.push_stats_processed(
        dispatcher, gathering, source_pid,
        txn_ids=dict(_STATS_TXN_ID),
        career_cash=career_cash,
    )
    gathering.expected_m12_pids = set()
    gathering.received_m12_pids = set()


def _cancel_m12_batch(gathering, reason: str) -> None:
    """Tear down a pending m=12 batch wait WITHOUT firing stats_processed.
    Used on EndGame (m=15) = unranked match end: no stats are reported, so the
    batch we optimistically armed at CloseParticipation must be cleared and its
    timeout cancelled. Idempotent — a second EndGame finds nothing to cancel."""
    if gathering.m12_timeout_handle is not None:
        try:
            gathering.m12_timeout_handle.cancel()
        except Exception:
            pass
        gathering.m12_timeout_handle = None
    gathering.expected_m12_pids = set()
    gathering.received_m12_pids = set()
    log.info("m=12 batch wait cancelled (gid=%d, reason=%s)", gathering.id, reason)


def _on_m12_timeout(dispatcher, gathering_id: int) -> None:
    """Called ~30s after the FIRST m=12 if not all participants have reported.
    Fires the batch with whatever data we have."""
    g = gatherings.get(gathering_id)
    if g is None:
        return
    if not g.received_m12_pids:
        # Nothing to push
        g.m12_timeout_handle = None
        return
    if g.received_m12_pids >= g.expected_m12_pids:
        # Already complete (race vs the all-reported fire path); nothing to do
        g.m12_timeout_handle = None
        return
    _fire_stats_processed_batch(dispatcher, g, reason="timeout")


def open_participation(dispatcher, conn, request: Request):
    """proto=60 m=23. Counterpart to m=19 — the host re-opens the lobby. Flip
    the closed flag back so the gathering reappears in browse / quickmatch."""
    gid = int.from_bytes(request.params[:4], "little") if len(request.params) >= 4 else 0
    changed = gatherings.set_closed(gid, False) if gid else False
    log.info("%s: OpenParticipation (m=23) gid=%d params(%dB)=%s — %s",
             conn.remote, gid, len(request.params), request.params.hex(),
             "reopened" if changed else "no-op (already open or unknown gid)")
    return _ok(request.call_id, METHOD_OPEN_PARTICIPATION, b"")


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_CREATE_GATHERING,   create_gathering)
    dispatcher.register(PROTO, METHOD_JOIN_GATHERING,     join_gathering)
    dispatcher.register(PROTO, METHOD_LEADERBOARD_SELF,   leaderboard_query)
    dispatcher.register(PROTO, METHOD_USER_STATS,         user_stats)
    dispatcher.register(PROTO, METHOD_FRIENDS_LIST,       social_list)
    dispatcher.register(PROTO, METHOD_REPORT_STATS,       lifecycle_stub)
    dispatcher.register(PROTO, METHOD_END_GAME,           lifecycle_stub)
    dispatcher.register(PROTO, METHOD_LEAVE_GATHERING,    leave_gathering_game)
    dispatcher.register(PROTO, METHOD_LEADERBOARD_GLOBAL, leaderboard_query)
    dispatcher.register(PROTO, METHOD_CLOSE_PARTICIPATION, close_participation)
    dispatcher.register(PROTO, METHOD_SEARCH_GATHERINGS,  search_gatherings)
    dispatcher.register(PROTO, METHOD_QUICK_MATCH,        quick_match)
    dispatcher.register(PROTO, METHOD_INVITATIONS_LIST,   social_list)
    dispatcher.register(PROTO, METHOD_OPEN_PARTICIPATION, open_participation)
    dispatcher.register(PROTO, METHOD_LIFECYCLE_26,       lifecycle_stub)
