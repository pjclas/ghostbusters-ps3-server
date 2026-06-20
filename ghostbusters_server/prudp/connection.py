"""Per-client PRUDP connection state.

PRUDP wire-protocol rules (this Quazal Rendez-Vous variant):

* `session_id`: each side chooses its own and stamps it on every outbound packet.
  Client picks in CONNECT, server picks in CONNECT+ACK.
* `connection_signature`: each side picks a random 4 bytes once, advertised in their
  SYN+ACK (server) or CONNECT (client). Stamped in those packets' connection_signature
  option field.
* `signature` field on every other packet (CONNECT, DATA, DISCONNECT) is just
  *the peer's connection_signature*. There is no HMAC on this variant — not even
  after Kerberos — so the field is a plain echo, not a keyed digest.
* `packet_id` rules:
    - On packets we send with FLAG_ACK: copy the client's pid we're acking.
    - On reliable DATA we originate: use our own counter starting at 1, increment per send.
    - SYN+ACK uses pid=0 (mirrors client's SYN pid=0).
    - CONNECT+ACK uses pid=1 (mirrors client's CONNECT pid=1).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field


CLIENT_TYPE = 3
CLIENT_PORT = 0xF
SERVER_TYPE = 3
SERVER_PORT = 0x1


@dataclass
class Connection:
    remote:     tuple              # (ip_str, udp_port) of the client
    local_port: int                # which of our UDP ports (30560 or 30561)

    state: str = "INITIAL"         # INITIAL → SYN_RECV → ESTABLISHED → CLOSED

    client_session_id: int = 0
    server_session_id: int = 0
    client_conn_sig:   bytes = b"\x00\x00\x00\x00"
    server_conn_sig:   bytes = b"\x00\x00\x00\x00"

    outgoing_reliable_seq: int = 1   # next pid for our originated reliable DATA
    last_client_pid:       int = 0   # highest client reliable pid we've seen / acked

    # Set during the secure-port CONNECT mutual-auth handshake (see
    # protocols/secure_connection.handle_connect_ack). Used to encrypt the
    # CONNECT+ACK token; not currently consumed afterwards (DATA payloads
    # use the static PRUDP RC4 key on this Quazal Rendez-Vous variant).
    session_key:     bytes = b""

    # Set during RegisterEx (proto 11 m4) on the secure connection.
    user_pid:        int = 0         # the Quazal PID this connection authenticated as
    rv_connection_id: int = 0        # server-assigned connection id returned to client
    station_urls:    tuple = ()      # client-advertised PRUDP URLs (local + later public)

    # Reassembly buffer for multi-fragment reliable DATA. Each fragment is
    # RC4-decrypted + zlib-decompressed independently; their plaintexts
    # concatenate into the final RMC body. Reset after flush. Accumulates
    # while fragment_id > 0; flushed when fragment_id == 0 arrives.
    fragment_buffer: bytes = b""

    last_activity: float = field(default_factory=time.monotonic)

    @classmethod
    def new(cls, remote, local_port) -> "Connection":
        c = cls(remote=remote, local_port=local_port)
        c.server_conn_sig = os.urandom(4)
        c.server_session_id = (os.urandom(1)[0] | 1)  # avoid 0, non-zero arbitrary value
        return c

    def touch(self) -> None:
        self.last_activity = time.monotonic()
