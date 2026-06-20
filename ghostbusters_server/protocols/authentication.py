"""Authentication protocol (proto 10).

Methods:
  1 Login(username:qString)
    → (result:u32=0x00010001, pid:u32, kerb_cipher:qBuffer, station_url:qString, trailer:10B)
  3 RequestTicket(source_pid:u32, target_pid:u32)
    → (result:u32=0x00010001, kerb_cipher:qBuffer)

Kerberos cipher generation uses the canonical Quazal key-derivation formula:
    K_user(pid) = MD5_iter(KDF_PASSWORD, 65000 + (pid % 1024))
See `crypto/kerberos.py` for the encrypt-then-MAC envelope and ticket layout.
The matching mutual-auth lookup lives in `protocols/secure_connection.py`.
"""

from __future__ import annotations

import logging

from .. import config, db
from ..crypto import kerberos
from ..db import accounts
from ..rmc.codec import Request, ResponseError, ResponseOK
from ..rmc import types as rt

log = logging.getLogger("auth")

PROTO = 10
METHOD_LOGIN          = 1
METHOD_REQUEST_TICKET = 3

QUAZAL_SUCCESS = 0x00010001

# 10-byte trailer following the station_url on Login responses. Its alignment
# is structurally significant — a one-byte shift makes the PS3 client silently
# abort after ACKing the response. The fields are an empty special-protocols
# list, a struct version word (0x01000001), and an empty server_name qString:
#   [u32 special_protocols_count=0][u32 0x01000001][u16 qString_len=0]
LOGIN_TRAILER = bytes.fromhex("00000000010000010000")


def _secure_station_url() -> str:
    # Must be the address the *client* uses to reach us, NOT our bind address.
    return (
        f"prudps:/address={config.PUBLIC_HOST};port={config.SECURE_PORT};"
        f"CID=1;PID={config.AUTH_PID};sid=1;stream=3;type=2"
    )


def login(dispatcher, conn, request: Request):
    try:
        reader = rt.Reader(request.params)
        username = reader.qstring()
    except Exception as e:
        log.warning("%s: Login parse failed: %s", conn.remote, e)
        return ResponseError(proto=PROTO, call_id=request.call_id, error_code=0x80030001)

    if not username:
        return ResponseError(proto=PROTO, call_id=request.call_id, error_code=0x80030002)

    con = db.open_db()
    try:
        pid = accounts.find_or_create_account(con, username)
    finally:
        con.close()

    # The ticket inside the kerb_cipher is opaque to the client; it forwards
    # the bytes to the secure service which decrypts them to extract the same
    # session_key. We use the same KDF formula for the service PID (1) so the
    # secure service can derive its own master without any shared state.
    cipher, _session_key = kerberos.build_login_cipher(
        client_pid=pid, secure_pid=config.SERVER_PID,
    )
    log.info("%s: Login(%r) → PID=%d (dynamic Kerberos, %dB cipher)",
             conn.remote, username, pid, len(cipher))

    out = bytearray()
    rt.w_u32(out, QUAZAL_SUCCESS)
    rt.w_u32(out, pid)
    rt.w_qbuffer(out, cipher)
    rt.w_qstring(out, _secure_station_url())
    out += LOGIN_TRAILER

    return ResponseOK(proto=PROTO, method=METHOD_LOGIN, call_id=request.call_id, ret=bytes(out))


def request_ticket(dispatcher, conn, request: Request):
    try:
        reader = rt.Reader(request.params)
        source_pid = reader.u32()
        target_pid = reader.u32()
    except Exception as e:
        log.warning("%s: RequestTicket parse failed: %s", conn.remote, e)
        return ResponseError(proto=PROTO, call_id=request.call_id, error_code=0x80030001)

    cipher, _session_key = kerberos.build_request_ticket_cipher(
        client_pid=source_pid, target_pid=target_pid,
    )
    log.info("%s: RequestTicket src=%d tgt=%d (dynamic Kerberos, %dB cipher)",
             conn.remote, source_pid, target_pid, len(cipher))

    out = bytearray()
    rt.w_u32(out, QUAZAL_SUCCESS)
    rt.w_qbuffer(out, cipher)

    return ResponseOK(proto=PROTO, method=METHOD_REQUEST_TICKET, call_id=request.call_id, ret=bytes(out))


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_LOGIN,          login)
    dispatcher.register(PROTO, METHOD_REQUEST_TICKET, request_ticket)
