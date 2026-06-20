"""PRUDP transport — thin wrapper over nintendoclients' PRUDPMessageV0
preconfigured for Ghostbusters (v0 with sig=0/flags=0/checksum=1)."""

from nintendo.nex import prudp, settings

from .. import config

TYPE_SYN        = prudp.TYPE_SYN
TYPE_CONNECT    = prudp.TYPE_CONNECT
TYPE_DATA       = prudp.TYPE_DATA
TYPE_DISCONNECT = prudp.TYPE_DISCONNECT
TYPE_PING       = prudp.TYPE_PING

FLAG_ACK      = prudp.FLAG_ACK
FLAG_RELIABLE = prudp.FLAG_RELIABLE
FLAG_NEED_ACK = prudp.FLAG_NEED_ACK
FLAG_HAS_SIZE = prudp.FLAG_HAS_SIZE
FLAG_MULTI_ACK = prudp.FLAG_MULTI_ACK

PRUDPPacket = prudp.PRUDPPacket


def _make_settings():
    s = settings.default()
    s["prudp.version"] = config.PRUDP_VERSION
    s["prudp.access_key"] = config.ACCESS_KEY.decode()
    s["prudp_v0.signature_version"] = config.PRUDP_SIGNATURE_VERSION
    s["prudp_v0.flags_version"]     = config.PRUDP_FLAGS_VERSION
    s["prudp_v0.checksum_version"]  = config.PRUDP_CHECKSUM_VERSION
    return s


_MESSAGE = prudp.PRUDPMessageV0(_make_settings())


def decode(raw: bytes):
    """Return list of PRUDPPacket parsed from one UDP datagram."""
    return _MESSAGE.decode(raw)


def encode(packet) -> bytes:
    return _MESSAGE.encode(packet)


def calc_connection_signature(addr) -> bytes:
    return _MESSAGE.calc_connection_signature(addr)
