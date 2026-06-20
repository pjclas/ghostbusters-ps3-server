"""Process-wide allocators for IDs that must be unique across all connections."""

from __future__ import annotations

import itertools
import threading

_lock = threading.Lock()
_connection_id_seq = itertools.count(1)
# Gathering IDs start at 10000. The high base keeps server-assigned IDs in a
# distinct range from the small IDs the client uses internally.
_gathering_id_seq = itertools.count(10000)


def next_connection_id() -> int:
    with _lock:
        return next(_connection_id_seq)


def next_gathering_id() -> int:
    with _lock:
        return next(_gathering_id_seq)
