"""Quazal primitive type codecs.

String:  qString = [u16 length-including-trailing-NUL] [chars] [\\x00]
Buffer:  qBuffer = [u32 length] [bytes]

Examples:
  Login REQUEST params (13B): `0b 00` + `myguy78_10` + `00`  → 11+2 = 13B, len incl null
  Login RESPONSE kerb_cipher: `58 00 00 00` + 88 bytes        → u32 size
  Login RESPONSE station_url: `4c 00` + 75 chars + `00`        → 76+2 = 78B, len incl null
"""

from __future__ import annotations

import struct


# --- write helpers ----------------------------------------------------------

def w_u8(buf: bytearray, v: int) -> None:
    buf.append(v & 0xFF)


def w_u16(buf: bytearray, v: int) -> None:
    buf += struct.pack("<H", v & 0xFFFF)


def w_u32(buf: bytearray, v: int) -> None:
    buf += struct.pack("<I", v & 0xFFFFFFFF)


def w_qstring(buf: bytearray, s: str) -> None:
    raw = s.encode("utf-8") + b"\x00"
    w_u16(buf, len(raw))
    buf += raw


def w_qbuffer(buf: bytearray, data: bytes) -> None:
    w_u32(buf, len(data))
    buf += data


# --- read helpers -----------------------------------------------------------

class Reader:
    """Cursor over a bytes object. Methods advance the offset."""

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def _take(self, n: int) -> bytes:
        if self.remaining() < n:
            raise ValueError(f"reader underflow: need {n} have {self.remaining()}")
        chunk = self.data[self.offset:self.offset + n]
        self.offset += n
        return chunk

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def qstring(self) -> str:
        n = self.u16()
        raw = self._take(n)
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    def qbuffer(self) -> bytes:
        n = self.u32()
        return self._take(n)

    def rest(self) -> bytes:
        chunk = self.data[self.offset:]
        self.offset = len(self.data)
        return chunk
