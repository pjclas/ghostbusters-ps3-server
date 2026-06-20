"""RMC dispatcher — decodes inbound RMC, looks up handler by (proto, method),
encodes the response, and hands it to the PRUDP transport for delivery.

Also exposes `send_request` for server-initiated RMC: the server pushes an
RMC Request (not a Response) to the client. Used for NAT traversal probes
(proto=3 m=2) and participant/stats notification events (proto=14). Client→server
and server→client RMC share the wire format; only the direction differs.
"""

from __future__ import annotations

import itertools
import logging
from typing import Callable, Dict, Tuple

from . import codec as rmc_codec
from .codec import Message, Request, ResponseError, ResponseOK
from .. import config
from ..prudp.connection import Connection
from ..prudp.server import PRUDPServer

log = logging.getLogger("rmc")

# Handler signature: (server, conn, request) -> ResponseOK | ResponseError
Handler = Callable[["RMCDispatcher", Connection, Request], Message]


class RMCDispatcher:
    """Holds the (proto, method) routing table and dispatches inbound payloads."""

    def __init__(self, prudp_server: PRUDPServer):
        self.prudp = prudp_server
        self.handlers: Dict[Tuple[int, int], Handler] = {}
        # Server-initiated RMC call_ids. Separate sequence from any client's —
        # each direction maintains its own. Starting at a large value keeps
        # them visually distinct from client-side ids in logs.
        self._server_call_id = itertools.count(0x10000)

    def register(self, proto: int, method: int, handler: Handler) -> None:
        self.handlers[(proto, method)] = handler

    def on_payload(self, conn: Connection, body: bytes) -> None:
        try:
            msg = rmc_codec.decode(body)
        except Exception as e:
            log.warning("%s: RMC decode failed: %s  body=%s", conn.remote, e, body[:48].hex())
            return

        if not isinstance(msg, Request):
            # Inbound RMC response to a server-initiated push (proto=3 NAT probe,
            # proto=14 notification event). This is the client reporting how it
            # received our push; we log it for observability but don't otherwise
            # act on it (pushes are fire-and-forget).
            if isinstance(msg, ResponseOK):
                log.info("%s: client reply OK proto=%d method=%d call_id=%d ret=%dB%s",
                         conn.remote, msg.proto, msg.method, msg.call_id, len(msg.ret),
                         f" body={msg.ret[:32].hex()}" if msg.ret else "")
            elif isinstance(msg, ResponseError):
                log.info("%s: client reply ERROR proto=%d call_id=%d error=0x%08x",
                         conn.remote, msg.proto, msg.call_id, msg.error_code)
            else:
                log.info("%s: ignoring inbound non-request %s", conn.remote, type(msg).__name__)
            return

        key = (msg.proto, msg.method)
        handler = self.handlers.get(key)
        if handler is None:
            log.warning("%s: no handler for proto=%d method=%d call_id=%d",
                        conn.remote, msg.proto, msg.method, msg.call_id)
            self._send(conn, ResponseError(proto=msg.proto, call_id=msg.call_id, error_code=0x80010001))
            return

        try:
            response = handler(self, conn, msg)
        except Exception as e:
            log.exception("%s: handler proto=%d method=%d raised", conn.remote, msg.proto, msg.method)
            self._send(conn, ResponseError(proto=msg.proto, call_id=msg.call_id, error_code=0x80020001))
            return

        self._send(conn, response)

    def _send(self, conn: Connection, msg: Message) -> None:
        body = rmc_codec.encode(msg)
        compress = (conn.local_port == config.SECURE_PORT)
        self.prudp.send_reliable_data(conn, body, compress=compress)

    def send_request(self, conn: Connection, proto: int, method: int,
                     params: bytes = b"") -> int:
        """Push a server-initiated RMC Request to `conn`. The client's reply
        comes back as a ResponseOK/Error that the dispatcher's normal inbound
        path silently drops (no completion tracking yet — not needed for fire-
        and-forget pushes like NAT m=2 or notification events). Returns the
        allocated call_id so callers can correlate against logs if needed."""
        call_id = next(self._server_call_id)
        req = Request(proto=proto, method=method, call_id=call_id, params=params)
        log.info("%s: server push proto=%d method=%d call_id=%d (%dB params)",
                 conn.remote, proto, method, call_id, len(params))
        self._send(conn, req)
        return call_id
