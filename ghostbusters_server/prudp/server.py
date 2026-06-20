"""PRUDP UDP listener — handshake + ACK + payload-handoff.

Layer above is RMC / protocol; we hand it the decrypted RMC body and a Connection
handle that knows how to send a reply.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from . import codec, payload as payload_layer
from .connection import (
    CLIENT_PORT, CLIENT_TYPE, SERVER_PORT, SERVER_TYPE,
    Connection,
)

log = logging.getLogger("prudp.server")

# A handler is called for each decrypted RMC body once a reliable DATA arrives.
# Signature: (connection, rmc_body_bytes) -> None  (sync; protocol layer can spawn tasks)
PayloadHandler = Callable[[Connection, bytes], None]

# Close hooks fire when a connection terminates (DISCONNECT packet or idle reap).
# Callbacks receive the client's (ip, port) remote tuple. Used to tear down
# gatherings owned by a host that disappeared without a clean back-out.
CloseHook = Callable[[Tuple[str, int]], None]

# A connect-ack handler computes the CONNECT+ACK payload from the incoming
# CONNECT payload (already deobfuscated+decompressed). Used by the secure
# port for dynamic Kerberos mutual auth — the response token depends on a
# check_value the client embedded in this specific CONNECT.
ConnectAckHandler = Callable[[Connection, bytes], bytes]


class PRUDPServer(asyncio.DatagramProtocol):
    """One instance per UDP port. Owns the connection registry for that port."""

    def __init__(self, local_port: int, on_payload: PayloadHandler):
        self.local_port = local_port
        self.on_payload = on_payload
        self.connections: Dict[Tuple[str, int], Connection] = {}
        self.transport: asyncio.DatagramTransport | None = None
        # Static CONNECT+ACK payload for services that have a fixed token
        # (none in production — kept for tests). The secure service uses
        # connect_ack_handler instead so the token is derived per-connection.
        self.connect_ack_payload: bytes = b""
        # Set on the secure port: compute a per-connection CONNECT+ACK token
        # by decrypting the client's ticket+reqd. See protocols/secure_connection.
        self.connect_ack_handler: Optional[ConnectAckHandler] = None
        # Hooks that fire on graceful DISCONNECT or idle-reap eviction.
        self.on_close: List[CloseHook] = []

    # --- asyncio DatagramProtocol --------------------------------------

    def connection_made(self, transport):
        self.transport = transport
        log.info("PRUDP listening on udp/%d", self.local_port)

    def datagram_received(self, raw: bytes, remote):
        try:
            packets = codec.decode(raw)
        except Exception as e:
            log.warning("%s: PRUDP decode failed (%dB): %s", remote, len(raw), e)
            return

        for pkt in packets:
            self._handle(pkt, remote)

    def error_received(self, exc):
        log.warning("udp/%d error: %s", self.local_port, exc)

    # --- per-packet dispatch -------------------------------------------

    def _handle(self, pkt, remote):
        conn = self.connections.get(remote)
        if pkt.type == codec.TYPE_SYN:
            self._handle_syn(pkt, remote)
        elif pkt.type == codec.TYPE_CONNECT:
            self._handle_connect(pkt, remote, conn)
        elif pkt.type == codec.TYPE_DATA:
            self._handle_data(pkt, remote, conn)
        elif pkt.type == codec.TYPE_PING:
            self._handle_ping(pkt, remote, conn)
        elif pkt.type == codec.TYPE_DISCONNECT:
            self._handle_disconnect(pkt, remote, conn)
        else:
            log.warning("%s: unknown PRUDP type %d", remote, pkt.type)

    def _handle_syn(self, pkt, remote):
        # New connection (or client reconnecting). Replace any prior state.
        conn = Connection.new(remote=remote, local_port=self.local_port)
        conn.state = "SYN_RECV"
        self.connections[remote] = conn
        log.info("%s: SYN — issuing SYN+ACK with conn_sig=%s",
                 remote, conn.server_conn_sig.hex())
        self._send_syn_ack(conn)

    def _handle_connect(self, pkt, remote, conn):
        if conn is None or conn.state != "SYN_RECV":
            log.warning("%s: CONNECT without SYN", remote)
            return
        if pkt.signature != conn.server_conn_sig:
            log.warning("%s: CONNECT signature mismatch (got %s expected %s)",
                        remote, pkt.signature.hex(), conn.server_conn_sig.hex())
            return
        conn.client_session_id = pkt.session_id
        conn.client_conn_sig = pkt.connection_signature
        conn.state = "ESTABLISHED"
        conn.touch()
        log.info("%s: CONNECT — sid_client=%d conn_sig_client=%s; ESTABLISHED",
                 remote, conn.client_session_id, conn.client_conn_sig.hex())

        ack_payload = self.connect_ack_payload
        if self.connect_ack_handler is not None and pkt.payload:
            try:
                incoming = payload_layer.unpack_compressed(
                    payload_layer.deobfuscate(pkt.payload)
                )
                ack_payload = self.connect_ack_handler(conn, incoming)
            except Exception as e:
                log.warning("%s: connect_ack_handler raised %s: %s",
                            remote, type(e).__name__, e)
                ack_payload = b""
        self._send_connect_ack(conn, client_pid=pkt.packet_id, ack_payload=ack_payload)

    def _handle_data(self, pkt, remote, conn):
        if conn is None or conn.state != "ESTABLISHED":
            log.warning("%s: DATA before connection established", remote)
            return
        conn.touch()

        # Pure ACK of one of our reliable packets — nothing to deliver upward.
        if (pkt.flags & codec.FLAG_ACK) and not pkt.payload:
            log.debug("%s: ACK of pid=%d", remote, pkt.packet_id)
            return

        if pkt.flags & codec.FLAG_RELIABLE:
            self._send_data_ack(conn, client_pid=pkt.packet_id)
            conn.last_client_pid = max(conn.last_client_pid, pkt.packet_id)

        if pkt.payload:
            try:
                body = payload_layer.unpack_compressed(payload_layer.deobfuscate(pkt.payload))
            except Exception as e:
                log.warning("%s: payload decrypt/decompress failed: %s", remote, e)
                return

            # PRUDP V0 fragmentation: fragment_id > 0 means "more fragments
            # follow"; fragment_id == 0 means "this is the last (or only)
            # fragment". Each fragment carries its own [u8 compression_ratio]
            # [zlib stream] framing — we already decompressed above — so the
            # plaintexts simply concatenate to form the full RMC body. This is
            # exercised by the host's ~1300B match-end m=12 ReportStats, which
            # spans several fragments.
            if pkt.fragment_id > 0:
                conn.fragment_buffer += body
                return
            if conn.fragment_buffer:
                body = conn.fragment_buffer + body
                log.info("%s: reassembled fragmented RMC: %dB total",
                         remote, len(body))
                conn.fragment_buffer = b""
            self.on_payload(conn, body)

    def _handle_ping(self, pkt, remote, conn):
        if conn is None:
            return
        conn.touch()
        if pkt.flags & codec.FLAG_NEED_ACK:
            self._send_ping_ack(conn, client_pid=pkt.packet_id)

    def _handle_disconnect(self, pkt, remote, conn):
        log.info("%s: DISCONNECT", remote)
        if conn is not None:
            self._send_disconnect_ack(conn, client_pid=pkt.packet_id)
            conn.state = "CLOSED"
        self._fire_close(remote)
        self.connections.pop(remote, None)

    def _fire_close(self, remote: Tuple[str, int]) -> None:
        for cb in self.on_close:
            try:
                cb(remote)
            except Exception:
                log.exception("on_close callback failed for %s", remote)

    def reap_idle(self, timeout_seconds: float) -> int:
        """Evict connections idle longer than timeout_seconds. Fires on_close
        hooks for each, so a host that hard-resets (no DISCONNECT packet)
        still has its owned gatherings cleaned up."""
        now = time.monotonic()
        stale = [c for c in self.connections.values()
                 if now - c.last_activity > timeout_seconds]
        for conn in stale:
            log.info("reaping idle connection %s (idle %.0fs)",
                     conn.remote, now - conn.last_activity)
            self._fire_close(conn.remote)
            self.connections.pop(conn.remote, None)
        return len(stale)

    # --- packet construction -------------------------------------------

    def _base_packet(self, conn: Connection, ptype: int, flags: int):
        p = codec.PRUDPPacket(type=ptype, flags=flags)
        p.version = 0
        p.source_type = SERVER_TYPE
        p.source_port = SERVER_PORT
        p.dest_type   = CLIENT_TYPE
        p.dest_port   = CLIENT_PORT
        p.fragment_id = 0
        p.payload = b""
        # Signature: peer's conn_sig (or zeros if peer hasn't sent one yet).
        p.signature = conn.client_conn_sig
        return p

    def _send_syn_ack(self, conn: Connection):
        p = self._base_packet(conn, codec.TYPE_SYN, codec.FLAG_ACK)
        p.session_id = 0
        p.packet_id = 0
        p.signature = b"\x00\x00\x00\x00"
        p.connection_signature = conn.server_conn_sig
        self._send(p, conn)

    def _send_connect_ack(self, conn: Connection, client_pid: int, ack_payload: bytes = b""):
        p = self._base_packet(conn, codec.TYPE_CONNECT, codec.FLAG_ACK)
        p.session_id = conn.server_session_id
        p.packet_id = client_pid
        p.signature = conn.client_conn_sig
        p.connection_signature = b"\x00\x00\x00\x00"
        if ack_payload:
            p.flags |= codec.FLAG_HAS_SIZE
            p.payload = payload_layer.obfuscate(
                payload_layer.pack_compressed(ack_payload, compress=False)
            )
        self._send(p, conn)

    def _send_data_ack(self, conn: Connection, client_pid: int):
        p = self._base_packet(conn, codec.TYPE_DATA, codec.FLAG_ACK)
        p.session_id = conn.server_session_id
        p.packet_id = client_pid
        self._send(p, conn)

    def _send_ping_ack(self, conn: Connection, client_pid: int):
        p = self._base_packet(conn, codec.TYPE_PING, codec.FLAG_ACK)
        p.session_id = conn.server_session_id
        p.packet_id = client_pid
        self._send(p, conn)

    def _send_disconnect_ack(self, conn: Connection, client_pid: int):
        p = self._base_packet(conn, codec.TYPE_DISCONNECT, codec.FLAG_ACK)
        p.session_id = conn.server_session_id
        p.packet_id = client_pid
        self._send(p, conn)

    def send_reliable_data(self, conn: Connection, body: bytes, compress: bool = False):
        """Send an RMC body upstream as a reliable DATA packet."""
        p = self._base_packet(
            conn,
            codec.TYPE_DATA,
            codec.FLAG_RELIABLE | codec.FLAG_NEED_ACK | codec.FLAG_HAS_SIZE,
        )
        p.session_id = conn.server_session_id
        p.packet_id = conn.outgoing_reliable_seq
        conn.outgoing_reliable_seq += 1
        p.payload = payload_layer.obfuscate(payload_layer.pack_compressed(body, compress=compress))
        self._send(p, conn)

    def _send(self, packet, conn: Connection):
        raw = codec.encode(packet)
        if self.transport is not None:
            self.transport.sendto(raw, conn.remote)


async def serve(local_port: int, on_payload: PayloadHandler) -> tuple[asyncio.DatagramTransport, PRUDPServer]:
    """Bind a PRUDPServer on local_port. Returns (transport, protocol)."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: PRUDPServer(local_port, on_payload),
        local_addr=("0.0.0.0", local_port),
    )
    return transport, protocol
