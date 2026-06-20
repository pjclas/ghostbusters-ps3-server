"""DNS shim — point the PS3 at this and the game finds your server.

The retail game looks up its online back-end by hostname. This shim answers that
one hostname with `PUBLIC_HOST` (your server) and FORWARDS every other lookup to
a real upstream resolver, so the console's normal internet / PSN name resolution
keeps working. That selective behavior is why you set the PS3's DNS to this shim
rather than blindly redirecting all traffic.

Typical use:
  1. Run this on the same machine as the server (server uses UDP 30560/30561, the
     shim uses UDP 53 — no conflict). Binding port 53 needs admin/root.
         Linux/macOS:  sudo python -m ghostbusters_server.dns_shim
         Windows:      run an elevated terminal, then
                       python -m ghostbusters_server.dns_shim
  2. On the PS3: Settings → Network Settings → Internet Connection Settings →
     Custom → ... → DNS Setting → Manual, and set Primary DNS to this machine's
     LAN IP. Save and test the connection.
  3. Go online in the game. Watch this shim's log: every lookup is printed. When
     you see the game's back-end hostname, add a distinctive substring of it to
     `DNS_HIJACK_DOMAINS` in config.py and restart the shim. (Or set
     `DNS_HIJACK_ALL = True` for a console that doesn't need real PSN sign-in.)

Configuration lives in config.py: DNS_BIND, DNS_PORT, DNS_UPSTREAM,
DNS_HIJACK_DOMAINS, DNS_HIJACK_ALL, and PUBLIC_HOST.
"""

from __future__ import annotations

import asyncio
import errno
import logging

from dnslib import A, DNSRecord, QTYPE, RCODE, RR

from . import config

log = logging.getLogger("dns_shim")

HIJACK_TTL = 60  # seconds; short so changes take effect quickly


def _should_hijack(qname: str) -> bool:
    """True if this hostname should resolve to PUBLIC_HOST instead of upstream."""
    if config.DNS_HIJACK_ALL:
        return True
    host = qname.rstrip(".").lower()
    return any(dom.lower() in host for dom in config.DNS_HIJACK_DOMAINS)


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """Forwards raw queries to the real resolver, matching replies by txn id."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self._pending: dict[int, asyncio.Future] = {}

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 2:
            return
        txid = int.from_bytes(data[:2], "big")
        fut = self._pending.pop(txid, None)
        if fut is not None and not fut.done():
            fut.set_result(data)

    async def query(self, raw: bytes, timeout: float = 4.0) -> bytes | None:
        if self.transport is None or len(raw) < 2:
            return None
        txid = int.from_bytes(raw[:2], "big")
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[txid] = fut
        self.transport.sendto(raw, (config.DNS_UPSTREAM, 53))
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(txid, None)
            return None


class _ShimProtocol(asyncio.DatagramProtocol):
    """Answers hijacked A queries locally; forwards the rest upstream."""

    def __init__(self, upstream: _UpstreamProtocol) -> None:
        self.upstream = upstream
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr) -> None:
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return
        if not req.questions:
            return
        qname = str(req.q.qname)
        client = addr[0]

        if req.q.qtype == QTYPE.A and _should_hijack(qname):
            reply = req.reply()
            reply.add_answer(
                RR(qname, QTYPE.A, rdata=A(config.PUBLIC_HOST), ttl=HIJACK_TTL))
            self.transport.sendto(reply.pack(), addr)
            log.info("HIJACK %-45s A -> %s  (%s)", qname, config.PUBLIC_HOST, client)
            return

        qtype = QTYPE.get(req.q.qtype, str(req.q.qtype))
        log.info("forward %-45s %-5s        (%s)", qname, qtype, client)
        resp = await self.upstream.query(data)
        if resp is not None:
            self.transport.sendto(resp, addr)
        else:
            reply = req.reply()
            reply.header.rcode = RCODE.SERVFAIL
            self.transport.sendto(reply.pack(), addr)
            log.warning("upstream timeout for %s — returned SERVFAIL", qname)


async def _main_async() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname).1s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    loop = asyncio.get_running_loop()

    # Upstream forwarder (ephemeral local port; sends to DNS_UPSTREAM:53).
    _, upstream = await loop.create_datagram_endpoint(
        _UpstreamProtocol, local_addr=("0.0.0.0", 0))

    # Public-facing shim listener.
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _ShimProtocol(upstream),
        local_addr=(config.DNS_BIND, config.DNS_PORT))

    mode = ("HIJACK_ALL (every A query)" if config.DNS_HIJACK_ALL
            else f"domains={config.DNS_HIJACK_DOMAINS or '[] (discovery only)'}")
    log.info("DNS shim listening on %s:%d", config.DNS_BIND, config.DNS_PORT)
    log.info("  hijack -> %s  |  %s", config.PUBLIC_HOST, mode)
    log.info("  upstream resolver: %s", config.DNS_UPSTREAM)
    log.info("Set your PS3's Primary DNS to this machine's LAN IP. Ctrl-C to stop.")

    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


def main() -> None:
    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        pass
    except PermissionError:
        log.error("Permission denied binding %s:%d — port 53 needs admin/root "
                  "(use sudo, or an elevated terminal on Windows).",
                  config.DNS_BIND, config.DNS_PORT)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            log.error(
                "Address already in use binding %s:%d. On most Linux hosts this "
                "is systemd-resolved, which holds port 53 on 127.0.0.53. A "
                "0.0.0.0 bind overlaps it. Fix: set DNS_BIND in config.py to this "
                "host's specific IP (e.g. its public IP) so it no longer overlaps "
                "the 127.0.0.53 stub — or disable the stub with "
                "'DNSStubListener=no' in /etc/systemd/resolved.conf and "
                "'systemctl restart systemd-resolved'.",
                config.DNS_BIND, config.DNS_PORT)
        elif exc.errno == errno.EADDRNOTAVAIL:
            log.error(
                "Cannot assign %s:%d — DNS_BIND must be an address configured on "
                "a local interface of this host (or 0.0.0.0). %r is not.",
                config.DNS_BIND, config.DNS_PORT, config.DNS_BIND)
        else:
            raise


if __name__ == "__main__":
    main()
