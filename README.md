# Ghostbusters PS3 — Custom Online Server

A clean-room, reverse-engineered replacement for the retired online multiplayer
servers of **Ghostbusters: The Video Game** on PlayStation 3 (NTSC `BLUS30307`).
The original Sony NP / Quazal Rendez-Vous back end was shut down years ago, which
took the game's entire online mode offline. This project reimplements that back
end so the online multiplayer can run again on a server you host yourself.

> ⚠️ **Educational / preservation project.** See the [Legal & Educational
> Notice](#legal--educational-notice) at the bottom before using it. No game
> code, assets, or copyrighted keys are distributed here — you bring your own
> from a copy of the game you legally own.

---

## What this is

When a PS3 copy of Ghostbusters: The Video Game goes online, it speaks a stack of
proprietary network protocols (Sony NP authentication on top of Quazal
Rendez-Vous / NEX, carried over the PRUDP transport). This server answers those
protocols byte-for-byte the way the official server did, reconstructed entirely
by **reverse-engineering the game's own network traffic and binary** — no
official server code or documentation was used.

The goal was **wire fidelity**: rather than re-deriving game rules, the server
reproduces exactly what the real server sent on the wire, so the unmodified
retail disc behaves online as it did on launch day.

### What works

This is a **faithful reimplementation of the original online experience**, with
one exception (friends — see below). Everything observed in the live protocol has
been reproduced:

- **Login & authentication** — full Sony NP Kerberos ticket flow; accounts are
  created automatically on first login (keyed by PSN ID).
- **Matchmaking & lobbies** — create / browse / quick-match / join gatherings,
  with the real filter system (game mode, level, job, difficulty, ranked).
- **Peer-to-peer setup** — NAT-traversal hole-punching so players actually
  connect to each other for the match itself (the game is P2P in-match).
- **Stats, leaderboards & trophies** — career stats and per-mode leaderboards
  persist in a database (store-and-serve model); online trophies pop correctly.
- **PS3 ↔ RPCS3 cross-play** — real consoles and the RPCS3 emulator can play
  together through the same server.

### The one exception: Friends

The **Friends and Invitations** social features are **not implemented**. Those
menus respond but return empty lists, so the rest of the game stays happy and
doesn't error. Everything else mirrors the original server. (Friends-based
matchmaking was a thin layer on top of the matchmaking that *is* implemented;
public/quick matchmaking is fully functional.)

---

## Stats, leaderboards & trophies

Online progression is reproduced **exactly as the original service worked** — the
server records and serves the same stat data the official back end did, so the
game behaves identically:

- **Career stats are tracked accurately.** Every online statistic the game
  reports at the end of a match — cash earned, ghosts trapped and destroyed, jobs
  completed, Most Wanted Ghosts captured, power-ups, top-earner standings, and
  the per-mode / per-level totals behind them — is persisted to the database and
  served back. Your career totals accumulate correctly across sessions and
  survive server restarts, just like on the original servers.

- **Leaderboards are real.** Every leaderboard category (overall cash, the four
  campaign boards, and each instant-action mode) ranks players by their actual
  recorded performance, with the same columns and ordering the original game
  showed.

- **All online trophies are awarded as the requirements are met.** Every online
  trophy unlocks the moment you satisfy its in-game requirement — exactly like on
  the official servers. The game's own trophy logic does the awarding; the
  server's job is to feed it accurate, faithfully-formatted stat data, which is
  precisely what it does. Meet the requirement, get the trophy.

Because this is a faithful store-and-serve reimplementation rather than a
reinterpretation of the game's rules, there's no separate progression system that
could drift out of sync — what you accomplish online counts just as it did
originally.

---

## How it works (architecture)

| Layer | Module | Role |
|-------|--------|------|
| Transport | `prudp/` | PRUDP v0 over two UDP ports (built on `nintendoclients`) |
| RMC framing | `rmc/` | Quazal RMC request/response codec + method dispatcher |
| Crypto | `crypto/` | Sony NP Kerberos master-key derivation; RC4 stream obfuscation |
| Protocols | `protocols/` | authentication, secure connection, account management, matchmaking, NAT, notifications, and the game protocol (proto 60: gatherings + stats) |
| State | `state/` | in-memory lobby/gathering registry |
| Persistence | `db/` | SQLite — accounts, career stats, leaderboards (with migrations) |

The server is a single-process `asyncio` application listening on two UDP ports
(`30560` auth, `30561` secure, by default).

---

## Requirements

- **Python 3.10+**
- Python packages (installed via `requirements.txt`):
  `nintendoclients`, `pycryptodome`, `anynet`, `dnslib`
- A way to point the console at this server. A small **DNS shim is included**
  (`ghostbusters_server/dns_shim.py`) — see
  [Pointing the PS3 at your server](#pointing-the-ps3-at-your-server).
- **The three game-extracted key constants** (see below). The server will not
  start without them.

---

## Installation

```sh
# 1. Clone
git clone https://github.com/pjclas/ghostbusters-ps3-server.git
cd ghostbusters-ps3-server

# 2. (Recommended) virtual environment
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

# 3. Install dependencies
pip install -r ghostbusters_server/requirements.txt

# 4. Provide your keys (see "What you must provide" below)
cd ghostbusters_server
cp local_keys.example.py local_keys.py     # then edit local_keys.py
cd ..

# 5. Set the address you advertise to clients
#    Edit ghostbusters_server/config.py and set PUBLIC_HOST to the IP that
#    BOTH your PS3 and any other clients can reach (your LAN IP for home use,
#    or your public IP for internet hosting). Ports default to 30560/30561.

# 6. Run
python -m ghostbusters_server.server
```

On startup the server initializes its SQLite database and binds both UDP
listeners. Accounts are created on demand the first time each PSN ID logs in —
there is no manual account setup.

---

## Pointing the PS3 at your server

The game finds its online back end by **hostname**, so you redirect that hostname
to your server using DNS. A DNS shim is included for this: it answers the game's
back-end hostname with your `PUBLIC_HOST` and **forwards every other lookup to a
real resolver**, so the console's normal internet / PSN name resolution keeps
working.

### 1. Run the DNS shim

Run it on the same machine as the server (the server uses UDP `30560/30561`, the
shim uses UDP `53` — no conflict). **Binding port 53 needs admin/root.**

```sh
# Linux / macOS
sudo python -m ghostbusters_server.dns_shim

# Windows: open an elevated (Administrator) terminal, then:
python -m ghostbusters_server.dns_shim
```

Settings live in `config.py` (`DNS_BIND`, `DNS_PORT`, `DNS_UPSTREAM`,
`DNS_HIJACK_DOMAINS`, `DNS_HIJACK_ALL`).

> **Linux hosts (systemd-resolved):** most Ubuntu/Debian/Fedora servers run
> systemd-resolved, which already holds port 53 on `127.0.0.53`. The default
> `DNS_BIND = "0.0.0.0"` overlaps that and fails with *"address already in
> use."* Either set `DNS_BIND` to the host's **specific IP** (e.g. its public
> IP) — which doesn't overlap the `127.0.0.53` stub — or disable the stub
> listener (`DNSStubListener=no` in `/etc/systemd/resolved.conf`, then
> `systemctl restart systemd-resolved`). Windows has no such collision, so the
> stock `0.0.0.0` works there as-is.
>
> If you bind to a public IP, **firewall UDP 53** to only the address your
> console connects from — otherwise the shim is an open forwarding resolver
> (abusable for DNS amplification).

### 2. Change the DNS server on your PS3

On the console:

1. **Settings → Network Settings → Internet Connection Settings**
2. Choose **Custom**, step through your connection (wired/Wi-Fi) keeping your
   normal settings until you reach **DNS Setting**.
3. Set **DNS Setting** to **Manual**.
4. **Primary DNS** = the **LAN IP of the machine running the shim**.
   **Secondary DNS** = a public resolver (e.g. `8.8.8.8`) as a fallback.
5. Finish the wizard, **Save**, and run **Test Connection**.

> Changing the PS3's DNS to the shim is required — that's what makes the console
> ask *your* machine where the game's servers are.

### 3. Identify the back-end hostname (one-time)

Out of the box the shim runs in **discovery mode**: it forwards everything and
**logs every lookup the PS3 makes**. With the shim running and the PS3 pointed at
it, start the game's online mode and watch the shim log. When you spot the game's
back-end hostname, add a distinctive substring of it to `DNS_HIJACK_DOMAINS` in
`config.py` and restart the shim — from then on that hostname resolves to your
server.

For a dedicated console that doesn't need real PSN sign-in, you can instead set
`DNS_HIJACK_ALL = True` to point **every** lookup at your server (don't use this
on a console that still needs Sony's name resolution).

---

## What you must provide

This repository deliberately ships **no copyrighted material**. To run a working
server you supply two things:

### 1. The three key constants (required)

These are constants **compiled into the game itself**, not secrets this project
can hand out. You recover them from your own legally-owned copy of the game and
place them in `ghostbusters_server/local_keys.py` (which is gitignored). Full
extraction instructions are in
[`ghostbusters_server/KEYS_README.md`](ghostbusters_server/KEYS_README.md).

| Key | What it is |
|-----|------------|
| `ACCESS_KEY` | Quazal PRUDP "access key" (packet HMAC + checksum seed) |
| `RC4_KEY` | PRUDP per-packet RC4 obfuscation key |
| `KDF_PASSWORD` | Sony NP Kerberos KDF seed (the standard PS3 NP "dummy password") |

If any are missing, the server exits at startup with an error pointing you back
to `KEYS_README.md`.

### 2. Network configuration (required)

- Set `PUBLIC_HOST` in `ghostbusters_server/config.py` to the IP address clients
  should use to reach the server. It ships as a `127.0.0.1` placeholder that will
  **not** work for a real console — change it to your machine's LAN IP (home use)
  or your public IP (internet hosting).
- Point your console/emulator at the server via the included DNS shim and by
  changing the PS3's DNS setting — see
  [Pointing the PS3 at your server](#pointing-the-ps3-at-your-server).

That's it — no game files, no server dumps, nothing else from the original
service is needed or included.

---

## Status & limitations

- ✅ Auth, matchmaking, P2P setup, stats, leaderboards, trophies, PS3 ↔ RPCS3
  cross-play.
- ❌ **Friends / Invitations** social lists (stubbed empty — see above).
- This is a hobby/preservation effort, reconstructed from observed behavior. It
  is provided as-is; expect rough edges around undocumented corners of the
  protocol.

---

## License

The server code in this repository is released under the **MIT License** — see
[`LICENSE`](LICENSE). This covers only this project's own source code; it grants
no rights to *Ghostbusters: The Video Game*, the PlayStation platform, or any
third-party material (see the notice below).

---

## Legal & Educational Notice

This project is published for **educational, research, and game-preservation
purposes** — to study the network protocols of a discontinued online service and
to keep a game playable after its official servers were permanently shut down.

- This is an **independent, clean-room reimplementation** created by analyzing
  network traffic and the game's own behavior. It contains **no code, assets, or
  data from the original game or its official servers.**
- It is **not affiliated with, endorsed by, or sponsored by** Sony Interactive
  Entertainment, Terminal Reality, Atari, Sony Pictures, or any rights holder of
  Ghostbusters or the PlayStation platform. All trademarks and copyrights are the
  property of their respective owners and are referenced for identification only.
- The key constants required to run the server are **not** distributed here. They
  are extracted by each user from their **own legally-owned copy** of the game.
- Use this software only with game copies you legally own, and only in compliance
  with the laws applicable to you. The authors provide it **as-is, without
  warranty of any kind**, and accept no liability for how it is used.
