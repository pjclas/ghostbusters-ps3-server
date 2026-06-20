"""AccountManagement protocol (proto 25).

Method 9 GetAccountInfoPublicData(pid:u32)
  Response is a 67-byte AccountInfoPublicData struct:
    u8=1 (Any-present marker)
    qString "AccountInfoPublicData"
    three u32 size fields (38, 34, 32)
    30 bytes of struct data
  The client does not require populated fields here, so the server returns an
  empty struct (all-zero data section). To surface real per-account data
  (display name, etc.) later, fill the 30-byte data section. The size fields
  are emitted with their fixed template values.
"""

from __future__ import annotations

import logging

from ..rmc.codec import Request, ResponseError, ResponseOK
from ..rmc import types as rt

log = logging.getLogger("account_mgmt")

PROTO = 25
METHOD_GET_ACCOUNT_INFO = 9

# 67-byte empty AccountInfoPublicData response (zeroed data section).
EMPTY_ACCOUNT_INFO_PUBLIC_DATA = bytes.fromhex(
    "01"                                                          # Any present marker
    "1600" "4163636f756e74496e666f5075626c69634461746100"          # qString "AccountInfoPublicData\0"
    "26000000" "22000000" "20000000"                              # 3 size fields (38, 34, 32)
    "000000000000000000000000000000000000000000000000000000000000" # 30 trailing zero bytes
)
assert len(EMPTY_ACCOUNT_INFO_PUBLIC_DATA) == 67


def get_account_info_public_data(dispatcher, conn, request: Request):
    try:
        r = rt.Reader(request.params)
        pid = r.u32()
    except Exception as e:
        log.warning("%s: GetAccountInfoPublicData parse failed: %s", conn.remote, e)
        return ResponseError(proto=PROTO, call_id=request.call_id, error_code=0x80030001)

    log.info("%s: GetAccountInfoPublicData(pid=%d) — empty template", conn.remote, pid)
    return ResponseOK(proto=PROTO, method=METHOD_GET_ACCOUNT_INFO,
                      call_id=request.call_id, ret=EMPTY_ACCOUNT_INFO_PUBLIC_DATA)


def register(dispatcher) -> None:
    dispatcher.register(PROTO, METHOD_GET_ACCOUNT_INFO, get_account_info_public_data)
