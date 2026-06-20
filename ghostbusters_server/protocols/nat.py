"""NAT traversal protocol (proto=3) — inbound side.

proto=3 m=2 (`InitiateProbe`) is a server-pushed call telling a host to
ping a joiner's URLs, opening the host's NAT mapping. We push this from
`join_gathering` after m=5 fires.

proto=3 m=1 (`RequestProbeInitiation`) is the joiner's pre-flight request,
fired right after a SearchGatherings or QuickMatch response. The joiner
sends the HOST's URLs (from the response) and asks the server to
coordinate a probe. The two join paths treat the probe differently:

- **Browse+manual-join** is lenient: PS3 fires m=1, waits ~6s without
  seeing any probe traffic, then fires m=5 anyway. The probe push from
  inside m=5 then opens NAT and the join succeeds.
- **Quick Match** is strict: PS3 fires m=1, waits for actual probe traffic
  to/from the host, and aborts (showing "no match found") if none
  arrives. Answering m=1 with an empty OK and no relay breaks Quick Match
  across any NAT direction that needs the host to ping first.

So m=1 relays the probe: parse the host URLs from the request, find the
host's connection in the gathering registry, and push proto=3 m=2 to that
host with the joiner's URLs. In the browse case the host then gets probed
twice (once here on m=1, once again from `join_gathering` on m=5), which
is harmless duplication.
"""

from __future__ import annotations

import logging

from ..rmc.codec import Request, ResponseOK
from ..rmc import types as rt
from ..state.gatherings import gatherings

log = logging.getLogger("nat")

PROTO = 3
METHOD_REQUEST_PROBE_INITIATION = 1
METHOD_INITIATE_PROBE           = 2


def _find_conn_by_urls(target_urls):
    """Look up the participant conn whose station_urls overlap with the given
    list, across every gathering. The URLs in an m=1 request name the peer the
    requester wants to hole-punch: that's the HOST (URLs from the m=20/m=21/m=5
    response) for the first probe, but for a 3rd+ player it's another GUEST
    whose URLs the requester learned via the host's P2P roster relay. Searching
    only hosts misses guest targets, so the guest<->guest InitiateProbe is never
    pushed and that pair's NAT hole-punch never opens. Search all participants'
    conns (host included). Returns None if no participant matches."""
    for g in gatherings.all_gatherings():
        for p in g.participants:
            pconn = getattr(p, "conn", None)
            if pconn is None:
                continue
            url_set = set(getattr(pconn, "station_urls", ()) or ())
            if any(u in url_set for u in target_urls):
                return pconn
    return None


def _probe_candidates(urls, same_nat: bool):
    """Pick which of a participant's station URLs to feed into a NAT probe.

    Two consoles behind the SAME public IP can only reach each other on their
    LAN candidate (station_urls[0], sid-less). Their WAN candidate is the shared
    public IP, which the router won't hairpin back to an inside host — probing it
    gets zero replies, and the console waits for that dead probe to time out
    (~10-18s) before committing to the LAN candidate that was reachable the whole
    time. So for a same-NAT pair, coordinate the punch on the LAN candidate only.
    Across NATs, hand out everything — there the WAN candidate is the one that
    works and the LAN one fails harmlessly."""
    urls = tuple(urls or ())
    if same_nat and urls:
        return (urls[0],)
    return urls


def request_probe_initiation(dispatcher, conn, request: Request):
    """proto=3 m=1: a participant asks the server to coordinate a NAT probe with
    another peer. The request names the TARGET (host for the first probe, or
    another guest for a 3rd+ player). Resolve the target's conn by URL, then open
    the punch in BOTH directions: push proto=3 m=2 InitiateProbe to the target
    (so it pings the requester) AND back to the requester (so it pings the
    target), for a simultaneous open.

    Same-NAT special case: if the requester and target share a public IP they're
    behind one router, so the punch is coordinated on LAN candidates only — the
    WAN candidate is an un-hairpinnable dead end that would just stall the
    connect (see `_probe_candidates`)."""
    try:
        r = rt.Reader(request.params)
        url_count = r.u32()
        target_urls = tuple(r.qstring() for _ in range(url_count))
    except Exception as e:
        log.warning("%s: NAT::RequestProbeInitiation parse failed: %s — empty OK",
                    conn.remote, e)
        return ResponseOK(proto=PROTO, method=METHOD_REQUEST_PROBE_INITIATION,
                          call_id=request.call_id, ret=b"")

    target_conn = _find_conn_by_urls(target_urls)
    if target_conn is None:
        log.info("%s: NAT::RequestProbeInitiation (m=1) — no participant matches "
                 "%d target URL(s); empty OK", conn.remote, len(target_urls))
        return ResponseOK(proto=PROTO, method=METHOD_REQUEST_PROBE_INITIATION,
                          call_id=request.call_id, ret=b"")

    same_nat = bool(getattr(conn, "remote", None)
                    and getattr(target_conn, "remote", None)
                    and conn.remote[0] == target_conn.remote[0])
    requester_urls = _probe_candidates(getattr(conn, "station_urls", ()), same_nat)
    target_urls_live = _probe_candidates(getattr(target_conn, "station_urls", ()), same_nat)

    # Leg 1: tell the target to ping the requester.
    for url in requester_urls:
        probe = bytearray()
        rt.w_qstring(probe, url)
        dispatcher.send_request(target_conn, PROTO, METHOD_INITIATE_PROBE, bytes(probe))
    # Leg 2: tell the requester to ping the target (simultaneous open).
    for url in target_urls_live:
        probe = bytearray()
        rt.w_qstring(probe, url)
        dispatcher.send_request(conn, PROTO, METHOD_INITIATE_PROBE, bytes(probe))

    log.info("%s: NAT::RequestProbeInitiation (m=1) — %s punch: pushed %d to target "
             "%s, %d back to requester",
             conn.remote, "same-NAT LAN-only" if same_nat else "bidirectional",
             len(requester_urls), target_conn.remote, len(target_urls_live))
    return ResponseOK(proto=PROTO, method=METHOD_REQUEST_PROBE_INITIATION,
                      call_id=request.call_id, ret=b"")


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_REQUEST_PROBE_INITIATION, request_probe_initiation)
