"""SecureConnection protocol (proto 11) + secure-port mutual-auth handshake.

Method 4 RegisterEx(station_urls:list<qString>, login_data:Any[<class>])
  Request:  [u32 list_count][N qString URLs] +
            [u16 class_name_len_incl_null][class_name+\\0][u32 data_size][data]
  Response: [u32 result=0x00010001][u32 connection_id][qString public_url]

The public_url echoed back is the client's NAT-mapped source address (what the
server actually sees on the wire), e.g. "prudp:/address=198.51.100.140;port=61018;sid=15;type=3".
The client uses this to know how peers should reach it.

Mutual-auth handshake (build_connect_ack_handler):
The PS3 sends the CONNECT packet with payload
    [u32 LE ticket_size][ticket bytes][u32 LE reqd_size][reqd bytes]
where `ticket` is the opaque blob the auth service handed it in the Login
response. We decrypt the ticket with K_user(SERVER_PID) to recover the same
session_key the client extracted, then decrypt `reqd` with session_key to get
the client's check_value. CONNECT+ACK payload =
    RC4(session_key).encrypt([u32 LE 4][u32 LE check_value+1])
"""

from __future__ import annotations

import logging
import struct

from .. import config
from ..crypto import kerberos
from ..prudp.connection import CLIENT_PORT, Connection
from ..rmc.codec import Request, ResponseError, ResponseOK
from ..rmc import types as rt
from ..state import registry

log = logging.getLogger("secure")

PROTO = 11
METHOD_REGISTER_EX = 4

QUAZAL_SUCCESS = 0x00010001


def handle_connect_ack(conn: Connection, incoming: bytes) -> bytes:
    """Mutual-auth handler for the secure port's PRUDP CONNECT.

    Raises ValueError on malformed input (caught by PRUDPServer, which then
    sends an empty CONNECT+ACK — the PS3 will time out and retry).
    """
    if len(incoming) < 8:
        raise ValueError(f"CONNECT payload too short: {len(incoming)}B")
    tsize = struct.unpack_from("<I", incoming, 0)[0]
    if tsize == 0 or 4 + tsize + 4 > len(incoming):
        raise ValueError(f"bad ticket_size {tsize} in {len(incoming)}B payload")
    ticket = incoming[4:4 + tsize]
    rsize_off = 4 + tsize
    rsize = struct.unpack_from("<I", incoming, rsize_off)[0]
    reqd_off = rsize_off + 4
    if reqd_off + rsize > len(incoming):
        raise ValueError(f"bad reqd_size {rsize}")
    reqd = incoming[reqd_off:reqd_off + rsize]

    # The PS3 forwards the RequestTicket ticket here (58B), NOT the Login
    # ticket (48B). RequestTicket was called with target_pid=AUTH_PID(=2), so
    # the inner ticket is encrypted with K_user(2) — hence we decrypt with
    # AUTH_PID. The secure service shares a PID with the auth service here;
    # SERVER_PID=1 is a separate role embedded in Login responses.
    session_key, source_pid = kerberos.extract_ticket_payload(ticket, config.AUTH_PID)
    _pid, _cid, check_value = kerberos.parse_reqd(reqd, session_key)
    conn.session_key = session_key
    conn.user_pid = source_pid  # so CreateGathering and gathering GC see the right owner
    log.info("%s: secure mutual-auth: pid=%d session_key=%s check=0x%08x",
             conn.remote, source_pid, session_key.hex(), check_value)
    return kerberos.build_connect_ack_token(session_key, check_value)


def _strip_sid(url: str) -> str:
    """Drop any `;sid=...` token from a PRUDP URL. The LAN candidate is served
    sid-less (`prudp:/address=192.168.x.y;port=15986;RVCID=N`); only the WAN
    candidate carries `sid=15;type=3`. Matching that wire shape makes the PS3
    treat the LAN entry as a same-subnet direct candidate."""
    return ";".join(t for t in url.split(";") if not t.startswith("sid="))


def _parse_any_class_name(reader: rt.Reader) -> tuple[str, bytes]:
    """Consume the Any header and data. Returns (class_name, data_bytes)."""
    name_len = reader.u16()
    raw_name = reader.data[reader.offset:reader.offset + name_len]
    reader.offset += name_len
    name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")
    data_size = reader.u32()
    data = reader.data[reader.offset:reader.offset + data_size]
    reader.offset += data_size
    return name, data


def register_ex(dispatcher, conn, request: Request):
    try:
        r = rt.Reader(request.params)
        url_count = r.u32()
        urls = tuple(r.qstring() for _ in range(url_count))
        login_class, login_data = _parse_any_class_name(r)
    except Exception as e:
        log.warning("%s: RegisterEx parse failed: %s", conn.remote, e)
        return ResponseError(proto=PROTO, call_id=request.call_id, error_code=0x80030001)

    if conn.rv_connection_id == 0:
        conn.rv_connection_id = registry.next_connection_id()
    cid = conn.rv_connection_id

    # The client's registered URLs are its LAN candidates. Hand them out
    # sid-less with a `;RVCID=N` suffix (the wire shape a peer expects for the
    # LAN entry, e.g. `prudp:/address=192.168.x.y;port=15986;RVCID=N`). These
    # are served alongside the WAN candidate below, UNFILTERED: the PS3 probes
    # both per peer and uses whichever answers (LAN for same-NAT peers, WAN for
    # remote). Do NOT filter LAN-vs-WAN server-side — consoles behind one NAT
    # interconnect via their LAN candidate while the WAN candidate hairpin-fails
    # harmlessly; stripping a candidate is what breaks a second console that
    # shares a public IP with another participant.
    urls_with_rvcid = tuple(f"{_strip_sid(u)};RVCID={cid}" for u in urls)

    # Construct a server-observed "peer-facing" WAN URL. BOTH the IP and the
    # port come from our view of the connection (conn.remote), i.e. the
    # NAT-mapped source endpoint the server actually received packets from.
    #
    # The port MUST be the observed source port (conn.remote[1]), NOT the
    # internal port the client baked into its own URL (urls[0], normally
    # 15986). The PS3 binds ONE PRUDP socket to 15986 and uses it for both the
    # server connection and P2P, so the NAT mapping the server observes for
    # this connection is exactly the mapping peers must send P2P to. On a flat
    # LAN the two are identical (observed source port == 15986), which is why
    # advertising the internal port worked there; behind real home NAT the
    # router commonly remaps 15986 -> some other external port and ONLY the
    # observed port is reachable. Advertising 15986 there means joiners punch
    # at publicIP:15986 (no mapping) and the join silently fails even though
    # the match is browse-visible. This matches response_public_url below.
    peer_facing_url = (
        f"prudp:/address={conn.remote[0]};port={conn.remote[1]};"
        f"sid={CLIENT_PORT};type=3;RVCID={cid}"
    )

    # Stash for later use: JoinGathering response section 1, proto=3 m=2 pushes,
    # eventually destroy-notifications, etc.
    conn.station_urls = urls_with_rvcid + (peer_facing_url,)

    log.info(
        "%s: RegisterEx client_urls=%s → station_urls=%s login=%s(%dB) cid=%d",
        conn.remote, urls, conn.station_urls, login_class, len(login_data), cid,
    )

    # The client-facing response URL reports the client its own observed public
    # endpoint (port = `conn.remote[1]`). The PS3 echoes this internally to
    # learn its WAN mapping; it is not the URL we hand out to peers.
    response_public_url = (
        f"prudp:/address={conn.remote[0]};port={conn.remote[1]};"
        f"sid={CLIENT_PORT};type=3"
    )

    out = bytearray()
    rt.w_u32(out, QUAZAL_SUCCESS)
    rt.w_u32(out, cid)
    rt.w_qstring(out, response_public_url)

    return ResponseOK(proto=PROTO, method=METHOD_REGISTER_EX, call_id=request.call_id, ret=bytes(out))


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_REGISTER_EX, register_ex)
