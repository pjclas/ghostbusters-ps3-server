"""Entrypoint. Boots the DB and binds both PRUDP listeners.
Protocol handlers (auth, secure connection, etc.) plug in via on_payload."""

from __future__ import annotations

import asyncio
import logging
import signal

from . import config, db, protocols
from .prudp.server import PRUDPServer, serve
from .protocols.secure_connection import handle_connect_ack
from .rmc.dispatcher import RMCDispatcher
from .state.gatherings import gatherings


# Idle-reap config. The PS3 sends a PRUDP TYPE_PING to the secure port every
# ~10 seconds, so 90s is a ~9x safety margin before we consider a connection
# dead. When a host hard-resets, eviction fires on_close so its owned gatherings
# are cleaned up.
IDLE_TIMEOUT_SECONDS = 90.0
REAP_INTERVAL_SECONDS = 15.0


async def _reaper(servers: list[PRUDPServer], stop: asyncio.Event) -> None:
    log = logging.getLogger("reaper")
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=REAP_INTERVAL_SECONDS)
            return  # stop was set during the wait
        except asyncio.TimeoutError:
            pass
        for srv in servers:
            try:
                srv.reap_idle(IDLE_TIMEOUT_SECONDS)
            except Exception:
                log.exception("reap_idle on udp/%d raised", srv.local_port)


async def _main_async() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname).1s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("server")

    con = db.init_db()
    log.info("db ready at %s", config.DB_PATH)
    con.close()
    # Stats persistence reads/writes the DB directly on each m=9/m=12 (the DB is
    # the single source of truth — no startup cache load needed).

    # Bind listeners first; dispatchers reference back into the PRUDPServer
    # so they can send reliable DATA.
    auth_t,   auth_srv   = await serve(config.AUTH_PORT,   lambda c, b: None)
    secure_t, secure_srv = await serve(config.SECURE_PORT, lambda c, b: None)

    auth_dispatch   = RMCDispatcher(auth_srv)
    secure_dispatch = RMCDispatcher(secure_srv)
    protocols.register_all(auth_dispatch)
    protocols.register_all(secure_dispatch)
    auth_srv.on_payload   = auth_dispatch.on_payload
    secure_srv.on_payload = secure_dispatch.on_payload

    # Clean up any gatherings owned by a connection when it closes.
    # Gatherings are only ever created on the secure connection (where user_pid
    # is set), but we register on both ports so the per-port remote tuple is
    # always matched correctly. Lookups on the auth side are O(n) no-ops.
    auth_srv.on_close.append(gatherings.destroy_by_owner_remote)
    secure_srv.on_close.append(gatherings.destroy_by_owner_remote)
    # Companion: when a non-host joiner's connection dies, drop them from any
    # gatherings they're in. (`destroy_by_owner_remote` ran first — if this
    # remote was a host, the gathering is already gone and we're a no-op.)
    auth_srv.on_close.append(gatherings.remove_participant_by_remote)
    secure_srv.on_close.append(gatherings.remove_participant_by_remote)

    # Secure-port CONNECT+ACK is the mutual-auth response: decrypt the client's
    # forwarded ticket with K_user(SERVER_PID), extract session_key, decrypt
    # reqd to get check_value, return RC4(session_key)([u32=4][u32 check+1]).
    secure_srv.connect_ack_handler = handle_connect_ack

    log.info("PRUDP up with %d auth + %d secure protocol handlers. Ctrl-C to stop.",
             len(auth_dispatch.handlers), len(secure_dispatch.handlers))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT,  stop.set)
        loop.add_signal_handler(signal.SIGTERM, stop.set)
    except NotImplementedError:
        # Windows asyncio doesn't support add_signal_handler — fall back to KeyboardInterrupt.
        pass

    # Idle reaper: evicts connections that stopped pinging (host powered off or
    # app crashed without a clean DISCONNECT) and fires on_close so their owned
    # gatherings are GC'd. Without it a silently-dead host leaves a gathering in
    # the registry indefinitely, and a later QuickMatch hands that dead lobby to
    # a new player who then can't connect to its long-gone host.
    reaper_task = asyncio.create_task(_reaper([auth_srv, secure_srv], stop))

    try:
        await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop.set()
        reaper_task.cancel()
        try:
            await reaper_task
        except (asyncio.CancelledError, Exception):
            pass
        auth_t.close()
        secure_t.close()
        log.info("listeners closed")


def main() -> None:
    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
