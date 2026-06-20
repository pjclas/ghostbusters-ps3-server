"""RMC framing for Ghostbusters' Quazal Rendez-Vous variant.

Wire layout (little-endian throughout):
  Request:        [u32 size][u8 proto|0x80][u32 call_id][u32 method][params...]
  Response (OK):  [u32 size][u8 proto][u8 success=1][u32 call_id][u32 method|0x00008000][return...]
  Response (ERR): [u32 size][u8 proto][u8 success=0][u32 err_code][u32 call_id]

`size` is the byte length of everything after itself (i.e. total - 4).

Note: the response-flag bit is 0x8000 (bit 15), not 0x80000000 (bit 31) like newer
Nintendo NEX. Discovered by wire round-trip — older Quazal Rendez-Vous convention.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Union

REQUEST_BIT          = 0x80
RESPONSE_METHOD_BIT  = 0x8000


@dataclass
class Request:
    proto:   int
    method:  int
    call_id: int
    params:  bytes = b""


@dataclass
class ResponseOK:
    proto:   int
    method:  int
    call_id: int
    ret:     bytes = b""


@dataclass
class ResponseError:
    proto:      int
    call_id:    int
    error_code: int


Message = Union[Request, ResponseOK, ResponseError]


def decode(body: bytes) -> Message:
    if len(body) < 5:
        raise ValueError(f"RMC body too short: {len(body)}B")

    size = struct.unpack_from("<I", body, 0)[0]
    if size + 4 != len(body):
        raise ValueError(f"RMC size mismatch: declared {size}, actual {len(body)-4}")

    proto_byte = body[4]
    proto = proto_byte & 0x7F

    if proto_byte & REQUEST_BIT:
        if len(body) < 13:
            raise ValueError(f"RMC request truncated: {len(body)}B")
        call_id, method = struct.unpack_from("<II", body, 5)
        return Request(proto=proto, method=method, call_id=call_id, params=body[13:])

    if len(body) < 6:
        raise ValueError(f"RMC response truncated: {len(body)}B")
    success = body[5]

    if success:
        if len(body) < 14:
            raise ValueError(f"RMC OK response truncated: {len(body)}B")
        call_id, raw_method = struct.unpack_from("<II", body, 6)
        return ResponseOK(
            proto=proto,
            method=raw_method & ~RESPONSE_METHOD_BIT,
            call_id=call_id,
            ret=body[14:],
        )

    if len(body) < 14:
        raise ValueError(f"RMC error response truncated: {len(body)}B")
    error_code, call_id = struct.unpack_from("<II", body, 6)
    return ResponseError(proto=proto, call_id=call_id, error_code=error_code)


def encode(msg: Message) -> bytes:
    if isinstance(msg, Request):
        body = (
            bytes([msg.proto | REQUEST_BIT])
            + struct.pack("<II", msg.call_id, msg.method)
            + msg.params
        )
    elif isinstance(msg, ResponseOK):
        body = (
            bytes([msg.proto & 0x7F, 1])
            + struct.pack("<II", msg.call_id, msg.method | RESPONSE_METHOD_BIT)
            + msg.ret
        )
    elif isinstance(msg, ResponseError):
        body = (
            bytes([msg.proto & 0x7F, 0])
            + struct.pack("<II", msg.error_code, msg.call_id)
        )
    else:
        raise TypeError(f"unknown RMC message type: {type(msg).__name__}")

    return struct.pack("<I", len(body)) + body
