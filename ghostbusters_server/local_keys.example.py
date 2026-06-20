"""Bring-your-own-keys template.

Copy this file to `local_keys.py` (which is gitignored) and fill in the three
byte-string values below. They are constants compiled into the game and are NOT
distributed here — recover them from your own legally-owned copy of the game.
See KEYS_README.md for exactly how to extract each one.

    cp local_keys.example.py local_keys.py   # then edit local_keys.py
"""

# Quazal PRUDP "access key" — packet HMAC + checksum seed.
# A short ASCII string compiled into the game's network init.
ACCESS_KEY = b""

# PRUDP per-packet RC4 obfuscation key (reset on every reliable DATA payload).
# A short ASCII string, alongside the access key in the binary.
RC4_KEY = b""

# Sony NP Kerberos KDF seed — the standard PS3 NP "dummy password".
# The same well-known constant every PS3 NP title uses.
KDF_PASSWORD = b""
