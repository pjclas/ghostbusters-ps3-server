"""Obfuscation + compression layers between PRUDP transport and RMC.

Layers applied to every reliable DATA payload:
- RC4 with the configured RC4_KEY, re-keyed per packet (Quazal Rendez-Vous
  behavior; newer NEX uses cumulative state).
- After RC4, the first byte is a zlib compression-ratio prefix.
    ratio = 0       → no compression, body follows as-is
    ratio > 0       → zlib-deflate the remainder; the value is a hint, not exact
- The auth port (30560) sends uncompressed (ratio=0); the secure port (30561)
  uses zlib.
"""

import zlib

from Crypto.Cipher import ARC4

from .. import config


def deobfuscate(payload: bytes) -> bytes:
    return ARC4.new(config.RC4_KEY).decrypt(payload)


def obfuscate(payload: bytes) -> bytes:
    return ARC4.new(config.RC4_KEY).encrypt(payload)


def unpack_compressed(data: bytes) -> bytes:
    if not data:
        return data
    ratio = data[0]
    if ratio == 0:
        return data[1:]
    return zlib.decompress(data[1:])


def pack_compressed(body: bytes, compress: bool = False) -> bytes:
    if not compress:
        return b"\x00" + body
    z = zlib.compress(body)
    ratio = max(1, min(255, len(body) // max(1, len(z))))
    return bytes([ratio]) + z
