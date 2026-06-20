"""MatchMaking protocol (proto 21) — the older Quazal Rendez-Vous variant this
game uses (proto 21, not the newer NEX 109).

Methods handled here:
  36 = DestroyGathering(gathering_id) — host-only
  39 = UpdateParticipantInfo          — joiner publishes initial state ~2s after Join

The leave/destroy split across protocols works like this:

    Guest leaves a lobby   → only `proto=60 m=16` fires
    Host  leaves a lobby   → `proto=21 m=36` then `proto=60 m=16`

Guests can't destroy a gathering, so the call they fire alone is "Leave":
`proto=60 m=16 = LeaveGathering` (fired by everyone). A host additionally fires
`m=36` first, which is `DestroyGathering`.
"""

from __future__ import annotations

import logging
import struct

from ..rmc.codec import Request, ResponseOK
from ..state.gatherings import gatherings
from . import notification

log = logging.getLogger("matchmaking")

PROTO = 21
METHOD_DESTROY_GATHERING = 36
METHOD_UPDATE_PARTICIPANT_INFO = 39


def update_participant_info(dispatcher, conn, request: Request):
    """proto=21 m=39. Fires ~2s after JoinGathering with the joiner's initial
    participant state.

    This is a client→server-only method: the game registers no receive-side
    handler for it, so pushing it back to a peer as a server request is
    rejected with 0x80010002 (Core::NotImplemented). The server therefore just
    acknowledges it and does not relay. Participant-state distribution between
    peers happens over their P2P channel, not through the server. See
    `notification.forward_update_participant_info` for the unused relay path.
    """
    log.info("%s: MM::UpdateParticipantInfo (m=39, %dB) — accepted (no relay)",
             conn.remote, len(request.params))
    return ResponseOK(proto=PROTO, method=METHOD_UPDATE_PARTICIPANT_INFO,
                      call_id=request.call_id, ret=b"")


def destroy_gathering(dispatcher, conn, request: Request):
    """proto=21 m=36. Host-only "destroy this gathering" call — fired when the
    host backs out of their own lobby. The host's own m=60.16 LeaveGathering
    follows immediately and is a no-op against the already-destroyed gathering.

    Owner check defensively included: in case a guest's PS3 ever fires this
    by accident, we don't want to let them nuke someone else's lobby."""
    if len(request.params) >= 4:
        gid = struct.unpack_from("<I", request.params, 0)[0]
    else:
        gid = 0
    g = gatherings.get(gid)
    if g is None:
        log.info("%s: MM::DestroyGathering(id=%d) — no-op (unknown id)",
                 conn.remote, gid)
    elif conn.user_pid == g.owner_pid:
        # Notify the other participants BEFORE destroying so they can update
        # their UIs ("host left, lobby closing"). After this returns, the
        # gathering is gone and we can't look up participants anymore.
        notification.push_leave(dispatcher, g, leaver_pid=conn.user_pid)
        gatherings.destroy(gid)
        log.info("%s: MM::DestroyGathering(id=%d, owner_pid=%d) — destroyed",
                 conn.remote, gid, conn.user_pid)
    else:
        log.warning("%s: MM::DestroyGathering(id=%d, pid=%d) — ignored, "
                    "caller is not the owner (owner_pid=%d)",
                    conn.remote, gid, conn.user_pid, g.owner_pid)
    return ResponseOK(proto=PROTO, method=METHOD_DESTROY_GATHERING,
                      call_id=request.call_id, ret=b"")


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_DESTROY_GATHERING, destroy_gathering)
    dispatcher.register(PROTO, METHOD_UPDATE_PARTICIPANT_INFO, update_participant_info)
