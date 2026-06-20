"""Process-global Gathering registry.

A Gathering is one matchmaking lobby. The registry owns their lifecycle:

1. **One active gathering per PID.** `create()` destroys any existing
   gathering owned by the same PID before allocating a new one, so a host that
   re-creates a lobby never leaves an orphan behind.
2. **Owner-disconnect cleanup.** `destroy_by_owner_remote()` is wired into
   the PRUDP server's `on_close` hook, so a host that disconnects (or whose
   connection is reaped by the idle-timeout) loses any gatherings they own.
3. **Joiner-disconnect cleanup.** `remove_participant_by_remote()` likewise
   removes a non-host participant from any gathering they were in when their
   PRUDP connection dies. The host learns they're gone via the next
   participant-notification push.

Each Gathering also stores the raw SparkGame param blob from the host's
CreateGathering request. SearchGatherings echoes it back with the
server-assigned gathering_id and owner_pid overlaid at fixed offsets, so every
field round-trips byte-for-byte without the server having to decode the opaque
settings section in the middle.

In-memory only — matchmaking state does not survive a server restart. The
SQLite persistence layer is for accounts and stats.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import registry


log = logging.getLogger("gatherings")

Remote = Tuple[str, int]

# Byte offsets inside the SparkGame Gathering struct, relative to the start of
# raw_params (after the leading class_name qString = "SparkGame", 12 bytes
# including the u16 length header).
GATHERING_ID_OFFSET = 0x14   # u32 LE
OWNER_PID_OFFSET    = 0x18   # u32 LE
DISPLAY_QSTRING_OFFSET = 0x34   # u16 LE length followed by content (incl null)
SETTINGS_BLOCK_SIZE    = 0x40   # 64 bytes between display qString and url_count
PARTICIPANT_COUNT_OFFSET_IN_SETTINGS = 0x11   # u32 LE: count of joined participants
# Slot config, offsets within the 64-byte settings block.
PUBLIC_SLOTS_OFFSET_IN_SETTINGS  = 0x0d   # u32 LE
PRIVATE_SLOTS_OFFSET_IN_SETTINGS = 0x15   # u32 LE
# Hard cap enforced by the game: host + 3 others.
MAX_PARTICIPANTS_PER_GATHERING = 4


@dataclass
class Participant:
    """A player currently in a gathering. The 16-byte `state` trailer rides on
    the wire in JoinGathering responses and participant-notification pushes; it
    carries the player's loadout / ready flags, written by UpdateParticipantInfo
    (proto=21 m=39) and zero until the player sends one."""
    pid: int
    display_name: str
    remote: Remote
    state: bytes = b"\x00" * 16
    # Secure Connection for this participant (typed loosely to avoid a
    # prudp->state circular import). Carries the RegisterEx-stashed
    # station_urls, so the NAT-probe coordinator can resolve a probe target by
    # URL whether it's the host or a guest. None if the entry was created
    # without a live connection.
    conn: Optional[Any] = None


@dataclass
class Gathering:
    id: int
    owner_pid: int
    owner_remote: Remote
    raw_params: bytes = b""             # exact bytes from CreateGathering
    created_at: float = field(default_factory=time.monotonic)
    # Host's Connection — typed loosely to avoid a prudp→state circular import.
    # Set by CreateGathering. Used by JoinGathering to read station_urls and to
    # push proto=3 m=2 NAT probes and participant notifications to the host.
    host_conn: Optional[Any] = None
    # All current participants, host first. The host is added to this list at
    # CreateGathering time so the participant block in JoinGathering responses
    # uniformly lists "everyone who's in" without special-casing the host.
    participants: List[Participant] = field(default_factory=list)
    # PIDs the host has invited to this gathering. An invited PID may join
    # even when the public slots are full (consuming a private slot instead).
    # Populated by the invite RMC handlers (proto=21 m=5).
    invited_pids: set = field(default_factory=set)
    # Set True by CloseParticipation (proto=60 m=19) — host has locked the
    # lobby (countdown started or match ended). Browse/QuickMatch must hide
    # closed gatherings so other players don't see a match they can't join.
    # OpenParticipation (m=23) resets to False.
    closed: bool = False

    # ---- End-of-match m=12 reporting state ----
    # All players who were in the match receive their stats update at the same
    # time, so the server waits for every participant to submit its m=12
    # ReportStats before firing the proto=14 stats_processed notification.
    # Snapshot taken at CloseParticipation (first call, when the lobby locks for
    # match-start) — the participant set we're waiting on for m=12s.
    expected_m12_pids: set = field(default_factory=set)
    # Set of pids that have actually sent m=12 since the snapshot.
    received_m12_pids: set = field(default_factory=set)
    # Handle to the 30s timeout task. asyncio.TimerHandle when armed; None when
    # not. Cancelled when the push fires (whether by completion or by timeout).
    m12_timeout_handle: Optional[Any] = None

    def _settings_slice(self) -> Optional[bytes]:
        """Return the 64-byte settings tail of raw_params, or None if the
        blob is malformed/short. Used by the slot-accounting methods."""
        rp = self.raw_params
        if len(rp) < DISPLAY_QSTRING_OFFSET + 2:
            return None
        dlen = int.from_bytes(rp[DISPLAY_QSTRING_OFFSET:DISPLAY_QSTRING_OFFSET + 2], "little")
        start = DISPLAY_QSTRING_OFFSET + 2 + dlen
        end = start + SETTINGS_BLOCK_SIZE
        if len(rp) < end:
            return None
        return rp[start:end]

    def public_slots(self) -> int:
        """Number of slots the host configured for browse-joinable players.
        Falls back to MAX-1 if settings are unreadable (fail-open: don't
        accidentally hide every match)."""
        s = self._settings_slice()
        if s is None:
            return MAX_PARTICIPANTS_PER_GATHERING - 1
        return int.from_bytes(s[PUBLIC_SLOTS_OFFSET_IN_SETTINGS:
                                PUBLIC_SLOTS_OFFSET_IN_SETTINGS + 4], "little")

    def private_slots(self) -> int:
        s = self._settings_slice()
        if s is None:
            return 0
        return int.from_bytes(s[PRIVATE_SLOTS_OFFSET_IN_SETTINGS:
                                PRIVATE_SLOTS_OFFSET_IN_SETTINGS + 4], "little")

    def public_remaining(self) -> int:
        """How many public slots are still open. Used by SearchGatherings
        + QuickMatch to filter the browse list, and by JoinGathering to
        validate stale-list joins. A participant counts against the public
        budget iff they were not invited — invited joiners take private
        slots instead. (When no invites are outstanding, every non-host
        participant counts against the public budget.)"""
        non_invited_joiners = sum(1 for p in self.participants
                                  if p.pid != self.owner_pid
                                  and p.pid not in self.invited_pids)
        return max(0, self.public_slots() - non_invited_joiners)

    def is_full(self) -> bool:
        """Hard cap from the game binary: 4 total participants including host."""
        return len(self.participants) >= MAX_PARTICIPANTS_PER_GATHERING

    def host_display_name(self) -> str:
        """Extract the host's bare username from the SparkGame display qstring.
        The full display is "<username> <loadout>" (e.g. "myguy78_09 1,12,1");
        the JoinGathering participant block uses just the username before the
        first space."""
        if len(self.raw_params) < DISPLAY_QSTRING_OFFSET + 2:
            return f"pid_{self.owner_pid}"
        dlen = int.from_bytes(
            self.raw_params[DISPLAY_QSTRING_OFFSET:DISPLAY_QSTRING_OFFSET + 2], "little"
        )
        start = DISPLAY_QSTRING_OFFSET + 2
        if start + dlen > len(self.raw_params):
            return f"pid_{self.owner_pid}"
        full = self.raw_params[start:start + dlen].rstrip(b"\x00").decode("utf-8", errors="replace")
        return full.split(" ", 1)[0]

    def render_join_embed(self, post_join_count: int) -> bytes:
        """Embedded gathering struct for the JoinGathering response.

        Same fixed offsets as render_settings_for_browse — gid@0x14,
        owner_pid@0x18, participant_count@settings+0x11 — but with two
        structural differences in the m=5 response:

          * No 7-byte injection and no trailing URL list. The host's URLs sit
            at the *start* of the m=5 response (section 1) instead.
          * The 0x40-byte settings block is truncated to 0x3F bytes. The very
            last byte (0x01 in the host's CreateGathering input) is dropped on
            the wire — keep it dropped or PS3 reads past end-of-struct.
        """
        if len(self.raw_params) < OWNER_PID_OFFSET + 4:
            return self.raw_params

        buf = bytearray(self.raw_params)
        buf[GATHERING_ID_OFFSET:GATHERING_ID_OFFSET + 4] = self.id.to_bytes(4, "little")
        buf[OWNER_PID_OFFSET:OWNER_PID_OFFSET + 4]       = self.owner_pid.to_bytes(4, "little")

        if len(buf) < DISPLAY_QSTRING_OFFSET + 2:
            return bytes(buf)
        display_len = int.from_bytes(buf[DISPLAY_QSTRING_OFFSET:DISPLAY_QSTRING_OFFSET + 2], "little")
        settings_start = DISPLAY_QSTRING_OFFSET + 2 + display_len
        settings_end   = settings_start + SETTINGS_BLOCK_SIZE
        if len(buf) < settings_end:
            return bytes(buf)

        pc_off = settings_start + PARTICIPANT_COUNT_OFFSET_IN_SETTINGS
        buf[pc_off:pc_off + 4] = post_join_count.to_bytes(4, "little")

        return bytes(buf[:settings_end - 1])

    def render_settings_for_browse(self) -> bytes:
        """Render this gathering's struct portion of a SearchGatherings list
        entry — class qstring, size words, gid, owner_pid, display name, and
        the settings tail TRUNCATED to 63 bytes (the 0x40th byte is the first
        byte of the trailing `[u32 url_group_count]` in the full response; see
        search_gatherings for why).

        Patches in the server-assigned gathering_id, owner_pid, and the
        joiner-count off-by-one for the lobby-browser icon row.

        URLs are NOT included here — they go in the separate trailing url-group
        list that the search_gatherings handler emits after all gathering
        structs. See `render_url_group_for_browse` for that piece.

        The SearchGatherings response is a list of these truncated structs
        followed by a list of url-groups: `struct*N` then `url_group*N`. The
        two lists are parallel and indexed by position, which is why the struct
        carries no URLs of its own.
        """
        if len(self.raw_params) < OWNER_PID_OFFSET + 4:
            return self.raw_params

        buf = bytearray(self.raw_params)
        buf[GATHERING_ID_OFFSET:GATHERING_ID_OFFSET + 4] = self.id.to_bytes(4, "little")
        buf[OWNER_PID_OFFSET:OWNER_PID_OFFSET + 4]       = self.owner_pid.to_bytes(4, "little")

        if len(buf) < DISPLAY_QSTRING_OFFSET + 2:
            return bytes(buf)
        display_len = int.from_bytes(buf[DISPLAY_QSTRING_OFFSET:DISPLAY_QSTRING_OFFSET + 2], "little")
        settings_start = DISPLAY_QSTRING_OFFSET + 2 + display_len
        settings_end   = settings_start + SETTINGS_BLOCK_SIZE
        if len(buf) < settings_end:
            return bytes(buf)

        pc_off = settings_start + PARTICIPANT_COUNT_OFFSET_IN_SETTINGS
        joiner_count = max(0, len(self.participants) - 1)
        buf[pc_off:pc_off + 4] = joiner_count.to_bytes(4, "little")

        # Truncate to settings_end - 1: drop the final byte of the 64-byte
        # settings tail. That byte is the first byte of the next u32 in the
        # outer wire format, not part of the settings struct.
        return bytes(buf[:settings_end - 1])

    def render_url_group_for_browse(self) -> bytes:
        """Render this gathering's entry in the trailing URL-group list of a
        SearchGatherings (m=20) or QuickMatch (m=21) response:
        `[u32 gid][u32 url_count][qstring url]*N`.

        Prefer the host's live `station_urls` (registered via RegisterEx)
        because they include the server-built peer-facing URL with the
        correct P2P port (15986). The URLs the host bakes into the
        CreateGathering blob carry the host's secure-connection source
        port (e.g. 52130) which is wrong for P2P — PS3 probes those and
        gives up before firing m=5, breaking Quick Match across NAT.
        m=5 JoinGathering already uses `station_urls` for its section-1
        URLs; this aligns m=20/m=21 with that behavior.

        Falls back to the raw_params URL bytes if a gathering has no
        host_conn / station_urls (defensive — real hosts always have them)."""
        if (self.host_conn is not None
                and getattr(self.host_conn, "station_urls", None)):
            urls = self.host_conn.station_urls
            out = bytearray()
            out += self.id.to_bytes(4, "little")
            out += len(urls).to_bytes(4, "little")
            for url in urls:
                url_bytes = url.encode("utf-8") + b"\x00"
                out += len(url_bytes).to_bytes(2, "little")
                out += url_bytes
            return bytes(out)

        # No-host_conn fallback: ship whatever URLs are in raw_params.
        if len(self.raw_params) < DISPLAY_QSTRING_OFFSET + 2:
            return b""
        display_len = int.from_bytes(
            self.raw_params[DISPLAY_QSTRING_OFFSET:DISPLAY_QSTRING_OFFSET + 2], "little")
        settings_end = DISPLAY_QSTRING_OFFSET + 2 + display_len + SETTINGS_BLOCK_SIZE
        if len(self.raw_params) < settings_end:
            return b""
        urls_blob = self.raw_params[settings_end:]    # [u32 url_count][qstring url]*N
        return self.id.to_bytes(4, "little") + urls_blob


class GatheringRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: Dict[int, Gathering] = {}
        self._owner_pid_to_id: Dict[int, int] = {}

    def create(self, owner_pid: int, owner_remote: Remote,
               raw_params: bytes = b"", host_conn: Optional[Any] = None) -> Gathering:
        with self._lock:
            existing_id = self._owner_pid_to_id.get(owner_pid)
            if existing_id is not None:
                self._by_id.pop(existing_id, None)
                log.info("auto-destroying stale gathering %d (pid=%d created a new one)",
                         existing_id, owner_pid)
            gid = registry.next_gathering_id()
            g = Gathering(id=gid, owner_pid=owner_pid, owner_remote=owner_remote,
                          raw_params=raw_params, host_conn=host_conn)
            # Host is participant #0 — the JoinGathering participant block
            # treats them uniformly with joiners.
            g.participants.append(Participant(
                pid=owner_pid,
                display_name=g.host_display_name(),
                remote=owner_remote,
                conn=host_conn,
            ))
            self._by_id[gid] = g
            self._owner_pid_to_id[owner_pid] = gid
            return g

    def add_participant(self, gathering_id: int, pid: int, display_name: str,
                        remote: Remote, conn: Optional[Any] = None) -> Optional[Participant]:
        """Append a joiner. No-op if they're already in the list (re-join after
        a flaky disconnect — keep the existing entry). Returns the entry.

        `conn` is the joiner's secure Connection; it's stored so the NAT-probe
        coordinator can resolve a probe target by URL when one participant asks
        to hole-punch another (not just the host). On a re-join we refresh the
        stored conn in case the participant reconnected with a new one."""
        with self._lock:
            g = self._by_id.get(gathering_id)
            if g is None:
                return None
            for p in g.participants:
                if p.pid == pid:
                    if conn is not None:
                        p.conn = conn
                    return p
            p = Participant(pid=pid, display_name=display_name, remote=remote,
                            conn=conn)
            g.participants.append(p)
            return p

    def remove_participant(self, gathering_id: int, pid: int) -> bool:
        """Remove a participant by pid. Does NOT destroy the gathering — the
        game decides via DestroyGathering (proto=60 m=16) when the lobby
        should die. Returns True if a participant was actually removed."""
        with self._lock:
            g = self._by_id.get(gathering_id)
            if g is None:
                return False
            before = len(g.participants)
            g.participants = [p for p in g.participants if p.pid != pid]
            return len(g.participants) != before

    def remove_participant_by_remote(self, remote: Remote) -> int:
        """Joiner disconnect cleanup. Removes the participant from every
        gathering they were in. Does NOT destroy gatherings — host-disconnect
        path (`destroy_by_owner_remote`) handles host hard-disconnects, and
        the game sends DestroyGathering when it wants the lobby gone."""
        with self._lock:
            removed = 0
            for g in self._by_id.values():
                # Skip the host's own gathering — destroy_by_owner_remote
                # handles that and would otherwise race against us.
                if g.owner_remote == remote:
                    continue
                before = len(g.participants)
                g.participants = [p for p in g.participants if p.remote != remote]
                if len(g.participants) != before:
                    removed += 1
            if removed:
                log.info("connection %s closed: removed from %d gathering(s) as participant",
                         remote, removed)
            return removed

    def set_closed(self, gathering_id: int, value: bool) -> bool:
        """Mark a gathering as closed (or re-open it). Returns True if the
        gathering exists and the state changed."""
        with self._lock:
            g = self._by_id.get(gathering_id)
            if g is None or g.closed == value:
                return False
            g.closed = value
            return True

    def destroy(self, gathering_id: int) -> bool:
        with self._lock:
            g = self._by_id.pop(gathering_id, None)
            if g is None:
                return False
            if self._owner_pid_to_id.get(g.owner_pid) == gathering_id:
                self._owner_pid_to_id.pop(g.owner_pid, None)
            return True

    def get(self, gathering_id: int) -> Optional[Gathering]:
        with self._lock:
            return self._by_id.get(gathering_id)

    def find_by_owner_pid(self, pid: int) -> Optional[Gathering]:
        with self._lock:
            gid = self._owner_pid_to_id.get(pid)
            return self._by_id.get(gid) if gid is not None else None

    def find_gatherings_containing_pid(self, pid: int) -> List[Gathering]:
        """Return every gathering this PID is currently a participant in.
        Typically just one, but the API is general — used for forwarding
        UpdateParticipantInfo (proto=21 m=39) broadcasts to the right set
        of participants."""
        with self._lock:
            return [g for g in self._by_id.values()
                    if any(p.pid == pid for p in g.participants)]

    def destroy_by_owner_remote(self, remote: Remote) -> int:
        with self._lock:
            victims: List[Gathering] = [g for g in self._by_id.values() if g.owner_remote == remote]
            for g in victims:
                self._by_id.pop(g.id, None)
                if self._owner_pid_to_id.get(g.owner_pid) == g.id:
                    self._owner_pid_to_id.pop(g.owner_pid, None)
            if victims:
                log.info("connection %s closed: GC'd %d gathering(s) %s",
                         remote, len(victims), [g.id for g in victims])
            return len(victims)

    def all_gatherings(self) -> List[Gathering]:
        with self._lock:
            return list(self._by_id.values())

    def reset(self) -> None:
        with self._lock:
            self._by_id.clear()
            self._owner_pid_to_id.clear()


gatherings = GatheringRegistry()
