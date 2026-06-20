# Bring your own keys

This server needs three constants that are **compiled into the Ghostbusters
game itself**. They are not secrets this project can hand out — they belong to
the game, and you recover them from your own legally-owned copy. Without them
the server cannot speak the game's PRUDP/Quazal or Sony NP auth protocols.

## Setup

```sh
cd ghostbusters_server
cp local_keys.example.py local_keys.py   # local_keys.py is gitignored
# edit local_keys.py and fill in the three byte strings
```

The server reads them through `config.py`; a missing or empty value raises a
clear error at startup pointing back here.

## The three values

| Name           | What it is                                              | How it's used in code |
|----------------|---------------------------------------------------------|-----------------------|
| `ACCESS_KEY`   | Quazal PRUDP "access key"                               | packet HMAC + checksum (`prudp/codec.py`) |
| `RC4_KEY`      | PRUDP per-packet RC4 obfuscation key                    | wraps every reliable DATA payload (`prudp/payload.py`) |
| `KDF_PASSWORD` | Sony NP Kerberos KDF seed (the PS3 "NP dummy password") | per-PID master-key derivation (`crypto/kerberos.py`) |

## How to recover them

You need the **decrypted** game executable (`EBOOT.BIN` → the main ELF/SELF).
Decrypting a `SELF` from a disc/PKG you own is a standard PS3 RE step (e.g. with
a SELF/SPRX decryptor such as `scetool`); that part is out of scope here.

### `ACCESS_KEY` and `RC4_KEY` — string-search the binary

Both are short printable-ASCII constants that the game passes into its Quazal
Rendez-Vous network init. The fastest path:

```sh
strings -n 4 EBOOT.elf | less
```

- The **access key** is the Quazal access string the title was built with. In
  Quazal games it is the argument handed to the Rendez-Vous client/credentials
  setup; it sits near the matchmaking/`quazal`/`rdv` strings.
- The **RC4 key** is the PRUDP stream-obfuscation key, a short ASCII constant
  near the access key. (PRUDP "encryption" is just RC4 with this fixed key — it
  is obfuscation, not real crypto.)

If string-searching is ambiguous, confirm at runtime: hook the function that
builds an outgoing PRUDP packet and read the key buffer it RC4s with, or hook
the credentials/access-key setter and read its argument — that pins down which
string plays which role.

### `KDF_PASSWORD` — the standard Sony NP dummy password

This one is **not game-specific**: every PS3 title that uses Sony NP auth seeds
its Kerberos KDF with the same well-known "dummy password" string. It is widely
documented in PS3 NP/Quazal reverse-engineering write-ups. You can confirm it on
your copy by hooking the key-derivation routine and reading the seed it iterates
with `MD5_iter(seed, 65000 + (pid % 1024))`.

## Why this isn't in the repo

These constants were removed from version control on purpose. Externalizing them
keeps the published source free of game-extracted material; it does **not** make
them globally secret, since anyone with the game can extract them the same way.
