"""Server-wide constants (network ports, advertised host, PIDs, crypto keys)."""

from pathlib import Path

# Network
AUTH_PORT   = 30560
SECURE_PORT = 30561
BIND_HOST   = "0.0.0.0"        # what we listen on (all interfaces)
PUBLIC_HOST = "127.0.0.1"     # CHANGE ME — what we ADVERTISE to clients in the secure
                                # station_url. Set this to the IP that BOTH your PS3 and any
                                # other clients can reach: your machine's LAN IP for home use,
                                # or your public IP for internet hosting. The 127.0.0.1
                                # placeholder will NOT work for a real console.

# PRUDP v0 (hybrid: sig=0, flags=0, checksum=1) — see STATUS.md "Decoder Pipeline"
PRUDP_VERSION = 0
PRUDP_SIGNATURE_VERSION = 0
PRUDP_FLAGS_VERSION     = 0
PRUDP_CHECKSUM_VERSION  = 1

# Keys are game-extracted constants and are NOT committed. Provide them locally:
# copy local_keys.example.py -> local_keys.py and fill in the values
# (see KEYS_README.md for how to recover them from your own copy of the game).
# The Kerberos master-key derivation in crypto/kerberos.py uses KDF_PASSWORD
# (per-PID, not a fixed string).
try:
    from . import local_keys as _keys
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "Missing ghostbusters_server/local_keys.py — copy local_keys.example.py "
        "to local_keys.py and fill in ACCESS_KEY / RC4_KEY / KDF_PASSWORD "
        "(see ghostbusters_server/KEYS_README.md)."
    ) from exc

ACCESS_KEY   = _keys.ACCESS_KEY     # PRUDP HMAC + checksum
RC4_KEY      = _keys.RC4_KEY        # per-packet RC4 reset on every reliable DATA payload
KDF_PASSWORD = _keys.KDF_PASSWORD   # Sony NP Kerberos KDF seed (per-PID derivation)

for _name in ("ACCESS_KEY", "RC4_KEY", "KDF_PASSWORD"):
    if not globals()[_name]:
        raise RuntimeError(
            f"{_name} is empty in ghostbusters_server/local_keys.py — fill it in "
            "(see ghostbusters_server/KEYS_README.md)."
        )

# RMC framing peculiarities for this Quazal Rendez-Vous variant
RMC_PROTO_REQUEST_FLAG = 0x80
RMC_METHOD_RESPONSE_FLAG = 0x80000000

# Service identity
SERVER_PID = 1
AUTH_PID   = 2
USER_PID_START = 10000
GATHERING_ID_START = 10000

# DB
DB_PATH = Path(__file__).parent / "server.db"
MIGRATIONS_DIR = Path(__file__).parent / "db" / "migrations"

# --- DNS shim (optional helper — see dns_shim.py) ---
# Point your PS3's DNS at the machine running the shim. It answers the game's
# back-end hostname with PUBLIC_HOST (this server) and forwards everything else
# to DNS_UPSTREAM, so normal internet / PSN name resolution keeps working.
DNS_BIND     = "0.0.0.0"   # interface the shim listens on (UDP 53). On a Linux host
                           # running systemd-resolved (most Ubuntu/Debian/Fedora), a
                           # 0.0.0.0 bind collides with the resolver's 127.0.0.53:53
                           # stub ("address already in use") — set this to the host's
                           # specific IP (e.g. its public IP) instead, which doesn't
                           # overlap 127.0.0.53. Windows has no such collision.
DNS_PORT     = 53          # standard DNS port (binding it usually needs admin/root)
DNS_UPSTREAM = "8.8.8.8"   # real resolver for any name we don't hijack
# Any A-record query whose hostname CONTAINS one of these substrings is answered
# with PUBLIC_HOST. Leave empty and watch the shim log to discover the exact
# hostname the game asks for, then add it here and restart.
DNS_HIJACK_DOMAINS: list[str] = [
    # e.g. "quazal", "ghostbusters", "<title-backend-host>"
]
# Dedicated-console shortcut: answer EVERY A query with PUBLIC_HOST. Only use this
# when the console does NOT need real PSN sign-in (it breaks Sony name lookups);
# otherwise keep it False and list specific hostnames in DNS_HIJACK_DOMAINS.
DNS_HIJACK_ALL = False
