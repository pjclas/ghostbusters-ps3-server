"""NotificationEvent server push (proto=14).

The server is the only entity that can tell clients about matchmaking-state
changes ("X joined the gathering", "X left"). Clients don't learn these from
each other, so without these pushes both consoles' lobby UIs stay empty after a
join. This module builds and sends those events.

Wire format (proto=14, RMC method=1 ProcessNotificationEvent):
  This game uses original Quazal Rendez-Vous (pre-NEX), which does NOT wrap the
  event in an Any[ClassName] envelope. The payload is the raw 4-field struct
  followed by a trailing string:
      [u32 source][u32 type][u32 param1][u32 param2][qString text]

Client dispatch contract:
  The client's RVGameContext dispatcher switches on the event CATEGORY
  (`type / 1000`) and silently drops any event in a category it doesn't handle:
      type/1000 == 900 → OnParticipantProcessed  (lobby roster)
      type/1000 == 901 → OnStatsProcessed         (career-stat cache)
      type/1000 ==   4 → OnOwnershipChange
  Within category 900 the action is selected by the SUBTYPE (`type % 1000`),
  each gated on whether the participant is already in the roster tree:
      900000 → ERASE participant from the roster    (acts only if present)
      900001 → set participant.state = 1 (active)    (acts only if present)
      900002 → INSERT participant into the roster    (acts only if absent)
  The INSERT path reads the event's `text` field as the new participant's
  station URL and stores it as that roster node's connection address.

This module pushes only what the lobby needs: a JOIN (900002) when a guest
joins and a LEAVE (900000) when a participant goes. Loadout / character / Ready
state travel P2P between consoles directly, so the server pushes nothing for
them.
"""

from __future__ import annotations

import logging
from typing import Iterable

from ..rmc import types as rt
from ..rmc.dispatcher import RMCDispatcher
from ..state.gatherings import Gathering, Participant

log = logging.getLogger("notification")

PROTO = 14
METHOD_PROCESS_EVENT = 1

# Event types. Category 900 = ParticipantProcessed; the subtype (% 1000)
# selects the action on the roster node. The dispatcher drops any event whose
# category (type / 1000) it doesn't handle, so these values must stay in the
# 900xxx range to reach the roster-update path.
EVENT_PARTICIPATION         = 900002   # subtype 2: JOIN — insert participant into roster
EVENT_PARTICIPATION_ACTIVE  = 900001   # subtype 1: set state=1 on existing node
EVENT_END_PARTICIPATION     = 900000   # subtype 0: LEAVE — erase participant from roster

# Category 901 = OnStatsProcessed. The dispatcher gates this branch on
# event.param1 == the current gathering id, but does not check the subtype, so
# any 901xxx reaches OnStatsProcessed. This is the channel that updates the
# client's local per-player career-cash cache (used by the lobby pre-match
# display and the wrap-up "Career Cash" label); pair it with m=12 ReportStats.
EVENT_STATS_PROCESSED       = 901001

# Transaction id for the param2 field. The client enforces strict-monotonic
# increment: the notification's param2 must be greater than the local
# stats_version it picked up from the ReadStats reply at login (the cat=101 h2
# field), or the broadcast is silently discarded. The txn id is per-PID and
# managed by the caller (game.py).


def _build_notification_event(source: int, type_: int,
                              param1: int = 0, param2: int = 0,
                              text: str = "") -> bytes:
    """Build the raw NotificationEvent payload for proto=14 method=1.
    No Any-wrapper — this is original Rendez-Vous (see module docstring for the
    field layout)."""
    out = bytearray()
    rt.w_u32(out, source)
    rt.w_u32(out, type_)
    rt.w_u32(out, param1)
    rt.w_u32(out, param2)
    rt.w_qstring(out, text)
    return bytes(out)


def _reachable_url_for(subject: Participant, recipient_remote) -> str:
    """Pick the station URL of `subject` that `recipient` can actually reach.

    This string is embedded as the JOIN event's text field; the client copies it
    verbatim into the new participant's roster node as that node's connection
    address (RVConnectionData.m_stationURL). The recipient then connects to that
    address directly — the same server-authoritative delivery the host already
    gets via the JoinGathering response's station-URL section.

    Why it matters: without a URL here the node is allocated with no address, so
    a participant only resolves if peer-to-peer discovery happens to find them.
    That's instant on a flat LAN (every candidate is directly reachable) but
    stalls — or never completes — when two consoles share one public IP over the
    internet, because the only address they discover for each other is the dead
    public-IP hairpin. The host never hits this because its URL is server-
    delivered; guests had no equivalent channel until this field.

    Selection: if subject and recipient share a public IP they're behind the
    same NAT, so hand out the LAN candidate (station_urls[0], sid-less) — the
    public-IP candidate would just hairpin-fail. Otherwise they're across NATs
    and need the WAN candidate (station_urls[-1], built from the observed port).
    """
    urls = getattr(getattr(subject, "conn", None), "station_urls", ()) or ()
    if not urls:
        return ""
    same_nat = bool(subject.remote and recipient_remote
                    and subject.remote[0] == recipient_remote[0])
    return urls[0] if same_nat else urls[-1]


def _broadcast(dispatcher: RMCDispatcher, recipients: Iterable[Participant],
               subject_pid: int, type_: int, gathering_id: int, label: str) -> int:
    """Push the event to each recipient via their secure-port Connection.
    Returns the number of pushes actually sent.

    Field semantics (as the client's OnParticipantProcessed reads them):
      - source: the participant whose state changed. Routing metadata; not read
        directly by the roster handler but follows standard Quazal convention.
      - type: category*1000 + subtype (900002 INSERT, 900001 active, 900000 ERASE).
      - param1: participant PID — the key into the client's roster tree. INSERT
        adds a node for this PID; ERASE removes it.
      - param2: gathering_id — the handler ignores the event unless this matches
        the client's active gathering id.
      - text: the INSERT path stores it as the new node's
        RVConnectionData.m_stationURL, so for an INSERT we send the subject's
        reachable station URL and the recipient's node gets a connection address
        directly from the server (see `_reachable_url_for`). ERASE removes the
        node, so it needs no URL. The URL is per-recipient (LAN vs WAN depends on
        whether the pair shares a NAT), so the payload is built inside the loop
        rather than once up front.
    """
    recipients = list(recipients)
    subject = next((p for p in recipients if p.pid == subject_pid), None)
    sent = 0
    for p in recipients:
        if p.pid == subject_pid:
            # The participant who is the *subject* of the event doesn't need
            # to be told about themselves — they already know they joined/left.
            continue
        conn = dispatcher.prudp.connections.get(p.remote)
        if conn is None:
            log.warning("notification %s(type=%d, subject=%d, gid=%d): no conn for "
                        "participant pid=%d remote=%s — skipping",
                        label, type_, subject_pid, gathering_id, p.pid, p.remote)
            continue
        url = (_reachable_url_for(subject, p.remote)
               if type_ == EVENT_PARTICIPATION and subject is not None else "")
        payload = _build_notification_event(
            source=subject_pid,
            type_=type_,
            param1=subject_pid,        # BST key into participants tree
            param2=gathering_id,       # gates the OnParticipantProcessed dispatch
            text=url,                  # RVConnectionData.m_stationURL for INSERT
        )
        dispatcher.send_request(conn, PROTO, METHOD_PROCESS_EVENT, payload)
        sent += 1
        if url:
            log.info("notification %s → recipient pid=%d: subject %d station_url=%s",
                     label, p.pid, subject_pid, url)
    if sent:
        log.info("notification %s(type=%d, subject=%d, gid=%d) → %d recipient(s)",
                 label, type_, subject_pid, gathering_id, sent)
    return sent


def push_join(dispatcher: RMCDispatcher, gathering: Gathering, joiner_pid: int) -> int:
    """Broadcast 'participant joined' to everyone in the gathering except the
    joiner themselves. Call AFTER add_participant so the joiner is in the
    list (we filter them out in _broadcast)."""
    return _broadcast(dispatcher, gathering.participants,
                      subject_pid=joiner_pid, type_=EVENT_PARTICIPATION,
                      gathering_id=gathering.id, label="join")


def push_participants_to_joiner(dispatcher: RMCDispatcher,
                                gathering: Gathering,
                                joiner_pid: int) -> int:
    """Push one type=900002 (INSERT) event to the new joiner for EACH
    participant in the gathering — including the joiner themselves. The
    self-event is what populates the joiner's own slot in their lobby UI.

    Why a self-event is needed: the host's CreateGathering handler inserts the
    host's own PID into its local participant roster, but the guest's
    JoinGathering handler has no equivalent local-insert path. Without a server
    push the guest's roster has no entry for itself, so the guest's own lobby
    slot renders blank. Sending the joiner an INSERT for its own PID fills it.

    Call AFTER add_participant so the joiner is in gathering.participants.
    """
    joiner = next((p for p in gathering.participants if p.pid == joiner_pid), None)
    if joiner is None:
        log.warning("push_participants_to_joiner(gid=%d, joiner=%d): "
                    "joiner not in participant list — call order wrong?",
                    gathering.id, joiner_pid)
        return 0
    joiner_conn = dispatcher.prudp.connections.get(joiner.remote)
    if joiner_conn is None:
        log.warning("push_participants_to_joiner(gid=%d, joiner=%d): "
                    "no conn for joiner remote=%s — skipping",
                    gathering.id, joiner_pid, joiner.remote)
        return 0

    sent = 0
    for p in gathering.participants:
        # Each existing participant's reachable station URL goes in the text
        # field so the joiner's node for them gets a connection address straight
        # from the server (see `_reachable_url_for`). For the self-event (p is
        # the joiner) this resolves to the joiner's own LAN URL, which the self
        # node ignores — harmless.
        url = _reachable_url_for(p, joiner.remote)
        payload = _build_notification_event(
            source=p.pid,
            type_=EVENT_PARTICIPATION,
            param1=p.pid,                 # BST key (participant's PID, including self)
            param2=gathering.id,          # gid gate
            text=url,                     # RVConnectionData.m_stationURL
        )
        dispatcher.send_request(joiner_conn, PROTO, METHOD_PROCESS_EVENT, payload)
        sent += 1
    if sent:
        log.info("notification backfill (gid=%d, joiner=%d) → %d participant(s) (incl. self)",
                 gathering.id, joiner_pid, sent)
    return sent


# Back-compat alias for callers that still use the old name. The new function
# also pushes a self-event; if a caller specifically does NOT want self-push,
# they should not use the alias.
push_existing_participants_to_joiner = push_participants_to_joiner


def push_stats_processed(dispatcher: RMCDispatcher, gathering: Gathering,
                         source_pid: int,
                         txn_ids: dict, career_cash: dict) -> int:
    """Broadcast a stats-processed notification (type=901001) to ALL participants
    of a gathering, with per-recipient targeted payload (Pattern A from the
    Quazal docs): each player's notification embeds their own SparkStats
    blob with new career totals in the text qString.

    Args:
      txn_ids:     dict[pid -> new stats_version]
      career_cash: dict[pid -> career cash float]

    Wire shape (proto=14 m=1 NotificationEvent per recipient):
      source = source_pid     (the m=12 sender; routing metadata)
      type   = 901001         (category 901; BST OnStatsProcessed)
      param1 = gathering.id   (GATE — dispatcher requires == current gid)
      param2 = recipient's txn_id (Quazal strict-monotonic-increment)
      text   = u16-prefixed SparkStats blob for this recipient:
                 u32 count=1
                 u32 pid       = recipient.pid
                 qString name  = "PID<n>"
                 u32 h2        = recipient's txn_id (consistency with cat=101)
                 u32 vec0_cnt=122 + 122 f32 zeros
                 u32 vec1_cnt=31  + 31 f32 (vec1[10] = recipient's career cash)
                 u32 vec2_cnt=0
    """
    import struct as _struct
    _VEC0_LEN, _VEC1_LEN, _VEC2_LEN = 122, 31, 0

    def _build_payload_for(recipient_pid: int) -> bytes:
        r_txn   = txn_ids.get(recipient_pid, 0)
        r_cash  = career_cash.get(recipient_pid, 0.0)
        # Build the SparkStats blob (binary; goes into text qString)
        s = bytearray()
        rt.w_u32(s, 1)
        rt.w_u32(s, recipient_pid)
        rt.w_qstring(s, f"PID{recipient_pid}")
        rt.w_u32(s, r_txn)
        rt.w_u32(s, _VEC0_LEN)
        for _ in range(_VEC0_LEN):
            s += _struct.pack("<f", 0.0)
        rt.w_u32(s, _VEC1_LEN)
        for i in range(_VEC1_LEN):
            s += _struct.pack("<f", r_cash if i == 10 else 0.0)
        rt.w_u32(s, _VEC2_LEN)
        stats_blob = bytes(s)
        # Build NotificationEvent with stats_blob as the text qString body
        out = bytearray()
        rt.w_u32(out, source_pid)
        rt.w_u32(out, EVENT_STATS_PROCESSED)
        rt.w_u32(out, gathering.id)
        rt.w_u32(out, r_txn)
        rt.w_u16(out, len(stats_blob))   # qString-style length prefix
        out += stats_blob                 # raw binary body (no NUL — explicit len)
        return bytes(out)

    sent = 0
    for p in gathering.participants:
        conn = dispatcher.prudp.connections.get(p.remote)
        if conn is None:
            log.warning("stats_processed (gid=%d, source=%d): no conn for "
                        "pid=%d remote=%s — skipping",
                        gathering.id, source_pid, p.pid, p.remote)
            continue
        payload = _build_payload_for(p.pid)
        dispatcher.send_request(conn, PROTO, METHOD_PROCESS_EVENT, payload)
        sent += 1
        log.info("stats_processed (gid=%d, source=%d) → pid=%d txn=%d cash=$%.0f (%dB payload)",
                 gathering.id, source_pid, p.pid,
                 txn_ids.get(p.pid, 0), career_cash.get(p.pid, 0.0), len(payload))
    return sent


def push_leave(dispatcher: RMCDispatcher, gathering: Gathering, leaver_pid: int) -> int:
    """Broadcast 'participant left' to everyone still in the gathering.
    Call AFTER remove_participant so the leaver is already gone from the
    list — `_broadcast`'s skip-self filter is then unnecessary, but harmless."""
    return _broadcast(dispatcher, gathering.participants,
                      subject_pid=leaver_pid, type_=EVENT_END_PARTICIPATION,
                      gathering_id=gathering.id, label="leave")


def forward_update_participant_info(dispatcher: RMCDispatcher,
                                    gathering: Gathering,
                                    sender_pid: int,
                                    raw_payload: bytes) -> int:
    """Re-push the joiner's UpdateParticipantInfo (proto=21 m=39) bytes to
    every OTHER participant in the gathering.

    Unused: this game registers no receive-side handler for proto=21 m=39, so a
    relayed copy is rejected with Core::NotImplemented (see
    matchmaking.update_participant_info). Participant state is instead exchanged
    P2P between consoles. Kept as a reference implementation of the relay path.

    Note: this isn't a NotificationEvent (proto=14). It's a relayed RMC Request
    on proto=21 m=39, carrying the joiner's original state payload verbatim, so
    a receiver would decode it as if it came from the joiner directly.
    """
    sent = 0
    for p in gathering.participants:
        if p.pid == sender_pid:
            continue
        conn = dispatcher.prudp.connections.get(p.remote)
        if conn is None:
            log.warning("forward m=39 (gid=%d, sender=%d): no conn for pid=%d remote=%s",
                        gathering.id, sender_pid, p.pid, p.remote)
            continue
        # Relay to receiver as a fresh server-initiated request.
        dispatcher.send_request(conn, 21, 39, raw_payload)
        sent += 1
    if sent:
        log.info("forward m=39 UpdateParticipantInfo(gid=%d, sender=%d, %dB) → %d recipient(s)",
                 gathering.id, sender_pid, len(raw_payload), sent)
    return sent
