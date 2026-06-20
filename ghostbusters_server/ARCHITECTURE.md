# Server Architecture

A custom server that lets *Ghostbusters: The Video Game* (PS3, BLUS30307)
play online again. It re-implements the game's original Quazal
Rendez-Vous / Sony NP back end: authentication, matchmaking lobbies,
peer-to-peer NAT traversal coordination, and career-stat / leaderboard
persistence. Clients connect to it exactly as they connected to the retail
service, using the same PRUDP transport, the same RMC protocols, and the same
wire formats.

The server is a coordinator and a store. It does not simulate gameplay and does
not compute game rules. Once a match starts, the consoles talk to each other
directly over P2P, and the server only stores the finished stats each client
uploads and serves them back. This "store-and-serve" stance shapes most of the
design, so it is worth keeping in mind throughout.

---

## 1. The big picture

```
   ┌─────────┐         UDP 30560 (auth)        ┌──────────────────────────┐
   │  PS3 /  │<───────────────────────────────>│       This server        │
   │  RPCS3  │        UDP 30561 (secure)       │                          │
   │  client │<───────────────────────────────>│    asyncio event loop    │
   └─────────┘                                 └──────────────────────────┘
        │                                                    │
        │ after the match starts,                            │  persists to SQLite:
        │ the consoles talk P2P                              │    accounts
        v                                                    v    career_stats
   ┌─────────┐   direct P2P (hole-punched)   ┌─────────┐          leaderboard_stats
   │   peer  │<─────────────────────────────>│   peer  │
   └─────────┘    gameplay, loadout, ready   └─────────┘
```

Two things never reach the server:

- In-match gameplay runs P2P between consoles.
- In-lobby state (loadout, ready) is also P2P, so the server's copy stays zero.

The server provides the connective tissue around those: it gets players
authenticated, lets them find and join each other's lobbies, helps them punch
through NAT, and persists the career numbers they report at match end.

---

## 2. The protocol stack

Every byte from a client passes up through these layers, and back down on the
way out. Each layer is one small module.

```
  UDP datagram                                   file
  ──────────────────────────────────────────────────────────────────
  PRUDP packet framing      (SYN/CONNECT/DATA)   prudp/codec.py, prudp/server.py
  Obfuscation + compression (RC4, then zlib)     prudp/payload.py
  RMC message framing       (request/response)   rmc/codec.py
  RMC dispatch              ((proto,method)->fn)  rmc/dispatcher.py
  Protocol handlers         (the actual logic)   protocols/*.py
  ──────────────────────────────────────────────────────────────────
```

### PRUDP (transport)

PRUDP is a reliable, ordered protocol layered on UDP. This title uses PRUDP v0
in a hybrid mode (`signature=0, flags=0, checksum=1`, see `config.py`). The raw
packet encode/decode comes from
[`nintendoclients`](https://github.com/kinnay/NintendoClients)' `PRUDPMessageV0`
(`prudp/codec.py`); the connection state machine and reliability sit on top of
it (`prudp/server.py`, `prudp/connection.py`).

Packet types handled: `SYN`, `CONNECT`, `DATA`, `PING`, `DISCONNECT`. Reliable
DATA is ACKed and reassembled from fragments. There is no HMAC on this variant,
so the per-packet `signature` field is just an echo of the peer's connection
signature.

### Obfuscation and compression (`prudp/payload.py`)

Every reliable DATA payload is:

1. RC4-encrypted with the fixed `RC4_KEY`, re-keyed on every packet (Quazal
   behavior; newer NEX uses a rolling stream).
2. Prefixed with a one-byte zlib compression-ratio marker (`0` means
   uncompressed).

The auth port (30560) sends uncompressed payloads. The secure port (30561) uses
zlib.

### RMC (remote method call), in `rmc/codec.py`

Once decrypted, the payload is an RMC message. Little-endian throughout:

```
Request:        [u32 size][u8 proto|0x80][u32 call_id][u32 method][params...]
Response (OK):  [u32 size][u8 proto][u8 1][u32 call_id][u32 method|0x8000][ret...]
Response (ERR): [u32 size][u8 proto][u8 0][u32 err_code][u32 call_id]
```

`size` is the length of everything after itself. The high bit `0x80` on the
proto byte marks a request. The response success flag rides bit `0x8000` of the
method field, which is the older Quazal convention rather than the `0x80000000`
that newer NEX uses.

### Dispatch (`rmc/dispatcher.py`)

`RMCDispatcher` holds a `{(proto, method): handler}` table. For each inbound
request it looks up the handler, calls it, and sends the response back down the
stack. An unknown `(proto, method)` returns a generic `0x80010001` error, and a
handler exception returns `0x80020001`.

The dispatcher also runs the reverse direction: `send_request()` pushes a
server-initiated RMC request to a client, which is how NAT probes and
notifications are delivered. Clients reply to those pushes with RMC responses;
the server logs them and drops them, since pushes are fire-and-forget.

---

## 3. The two ports

The retail design splits the service across two UDP listeners, and this server
mirrors that. Both run the same RMC dispatch table (every protocol is registered
on both), but they play different roles:

| Port | Name | Role |
|------|------|------|
| 30560 | auth | Login and ticket issuance. Uncompressed payloads. No mutual auth on CONNECT. |
| 30561 | secure | Everything after login: RegisterEx, matchmaking, stats. zlib payloads. CONNECT performs Kerberos mutual auth. |

A client logs in on the auth port, gets a Kerberos ticket, then opens a second
connection to the secure port and proves it holds the ticket during the CONNECT
handshake. From then on all real work happens on the secure connection, which is
the one that carries `user_pid`.

---

## 4. Directory map

```
ghostbusters_server/
├── server.py            Entrypoint: boots DB, binds both ports, wires hooks, runs reaper
├── config.py            All constants: ports, PUBLIC_HOST, PIDs, DB paths, DNS-shim config
├── local_keys.py        Game-extracted keys (gitignored; see KEYS_README.md)
│
├── prudp/               Transport layer
│   ├── codec.py         PRUDP v0 packet encode/decode (wraps nintendoclients)
│   ├── connection.py    Per-client Connection dataclass + handshake state
│   ├── payload.py       RC4 + zlib obfuscation/compression
│   └── server.py        asyncio DatagramProtocol; handshake, reliability, fragments, reaper
│
├── rmc/                 RMC layer
│   ├── codec.py         RMC request/response framing
│   ├── dispatcher.py    (proto,method) routing; server->client push
│   └── types.py         Quazal primitive read/write helpers (qString, qBuffer, u32)
│
├── crypto/
│   └── kerberos.py      Quazal/NP Kerberos: key derivation, ticket build/parse, mutual auth
│
├── protocols/           One module per RMC protocol (the business logic)
│   ├── authentication.py     proto 10  Login, RequestTicket
│   ├── secure_connection.py  proto 11  RegisterEx + the secure-port CONNECT mutual auth
│   ├── account_management.py proto 25  GetAccountInfoPublicData
│   ├── nat.py                proto 3   NAT-probe coordination
│   ├── matchmaking.py        proto 21  DestroyGathering, UpdateParticipantInfo
│   ├── notification.py       proto 14  server->client push events
│   └── game.py               proto 60  matchmaking + stats (the largest module)
│
├── state/               In-memory (non-persistent) state
│   ├── gatherings.py    GatheringRegistry: all active lobbies + participants
│   └── registry.py      Process-wide ID allocators (connection ids, gathering ids)
│
├── db/                  Persistence
│   ├── connection.py    SQLite open + migration runner
│   ├── accounts.py      find_or_create_account, name_for_pid
│   ├── career.py        career_stats + leaderboard_stats store/serve
│   └── migrations/*.sql Schema (applied once, tracked in _migrations)
│
└── dns_shim.py          Optional helper: points the console's DNS at this server
```

---

## 5. Connection lifecycle

```
   client                          server (prudp/server.py)
     │  SYN ────────────────────>   new Connection, pick server_conn_sig
     │  <──────────────── SYN+ACK   (advertises server_conn_sig)
     │  CONNECT ────────────────>   verify sig; record client sid + sig; ESTABLISHED
     │                              (secure port: run mutual auth on the payload)
     │  <──────────── CONNECT+ACK   (secure port: the auth token)
     │  DATA (reliable, RMC) ───>   ACK + decrypt + dispatch
     │  <──────────────────  DATA   (RMC response)
     │  PING <──> PING+ACK          (every ~10s keepalive)
     │  DISCONNECT ─────────────>   fire on_close hooks (gathering cleanup)
```

A `Connection` (`prudp/connection.py`) holds the remote `(ip, port)`, both sides'
session ids and connection signatures, the reliable-sequence counters, a
fragment-reassembly buffer, and (once authenticated) the `user_pid`,
`station_urls`, and `session_key`.

Idle reaping: a background task (`server.py::_reaper`) evicts connections idle
longer than 90 s and fires their `on_close` hooks, so a console that powers off
without a clean DISCONNECT does not leave a dead lobby in the registry.

---

## 6. Authentication and crypto (`protocols/authentication.py`, `crypto/kerberos.py`)

```
  Login(username)                 -> pid, kerb_cipher, secure-port station_url
  RequestTicket(src_pid, tgt_pid) -> kerb_cipher (ticket for the secure service)
```

All keys derive from one formula:

```
  K_user(pid) = MD5_iter(KDF_PASSWORD, 65000 + (pid % 1024))
```

The auth service encrypts a session key into a `kerb_cipher` (an RC4 plus
HMAC-MD5 envelope) that the client cannot read but forwards to the secure
service. The secure service derives the same `K_user`, decrypts the ticket,
recovers the same session key, and the two sides are mutually authenticated. The
full ticket and mutual-auth byte layout is documented at the top of
`crypto/kerberos.py`.

The secure-port CONNECT handshake (`secure_connection.handle_connect_ack`)
decrypts the forwarded ticket, extracts the session key and check value, and
returns `[u32 4][u32 check+1]`. The server proves it knew the session key by
parsing the request correctly, not by encrypting the reply.

New usernames get a PID allocated from the `counters.next_pid` row starting at
10000 (`db/accounts.py`).

---

## 7. The protocol surface

Every registered `(proto, method)` handler:

| Proto | Method | Name | What it does |
|------:|-------:|------|--------------|
| 10 | 1 | Login | username to pid + Kerberos cipher + secure station URL |
| 10 | 3 | RequestTicket | issue a ticket for the secure service |
| 11 | 4 | RegisterEx | client registers its station URLs; server returns a connection id and the client's observed public URL |
| 25 | 9 | GetAccountInfoPublicData | returns an (empty) account-info struct |
| 3 | 1 | RequestProbeInitiation | client asks the server to coordinate a NAT punch with a peer |
| 21 | 36 | DestroyGathering | host destroys its lobby |
| 21 | 39 | UpdateParticipantInfo | joiner publishes lobby state (accepted, not relayed) |
| 60 | 4 | CreateGathering | create a lobby; returns the assigned gathering id |
| 60 | 5 | JoinGathering | join; returns host URLs + participant list + embedded gathering |
| 60 | 16 | LeaveGathering | caller leaves (host and guest both send) |
| 60 | 19 | CloseParticipation | host locks the lobby (countdown / match end) |
| 60 | 23 | OpenParticipation | host re-opens the lobby |
| 60 | 20 | SearchGatherings | filtered list of joinable lobbies |
| 60 | 21 | QuickMatch | first matching open lobby, as a 1-element list |
| 60 | 26 | (lifecycle) | fires after m19 at match-start; no-op |
| 60 | 15 | EndGame | unranked match end (cancels the stats-batch wait) |
| 60 | 7 | GetLeaderboardStatsAroundSelf | leaderboard window around the requester ("Personal") |
| 60 | 17 | GetLeaderboardStats | top-N leaderboard page ("Global") |
| 60 | 9 | ReadStats | per-user career blob (Player Stats / Most Wanted Ghosts) |
| 60 | 12 | ReportStats | match-end career upload (persisted) |
| 60 | 10 / 22 | Friends / Invitations | social menu lists (empty stubs) |

Proto 14 (NotificationEvent) is server-to-client only and has no inbound
handler.

---

## 8. Matchmaking subsystem

State lives entirely in memory in `state/gatherings.py`. A `GatheringRegistry`
holds `Gathering` objects, each with its participant list, the raw SparkGame
settings blob the host uploaded, and the host's live `Connection`. Nothing about
lobbies is persisted, because matchmaking state does not need to survive a
restart.

Lifecycle of a match:

```
  Host:  CreateGathering    ──>  registry stores raw blob, assigns gid, host = participant #0
  Guest: SearchGatherings   ──>  filtered list (gid + owner + settings + host URLs)
  Guest: (proto 3 m1)       ──>  server coordinates NAT punch with host
  Guest: JoinGathering      ──>  added to participant list; gets:
                                   (1) host station URLs
                                   (2) existing participants
                                   (3) embedded gathering (post-join count)
                                 server pushes:
                                   - proto 3 m2 NAT probe to host
                                   - proto 14 JOIN notification to existing players
                                   - proto 14 backfill (all participants incl. self) to joiner
  Host:  CloseParticipation ──>  lobby locked and hidden; snapshot expected stat reporters
  ...match plays out P2P...
  All:   ReportStats (m12)   ──>  each player's career persisted; once ALL report, stats push
  Host:  DestroyGathering    ──>  lobby removed, remaining players notified
```

The raw SparkGame blob is echoed back with the assigned `gathering_id` and
`owner_pid` overlaid at fixed byte offsets, so every host-chosen setting
round-trips without the server having to decode the opaque settings section.
`SearchGatherings` and `QuickMatch` filter the list by slot availability, the
`closed` flag, and (Search only) the request's filter blob.

Disconnect cleanup is wired through PRUDP `on_close` hooks (`server.py`): a host
disconnect destroys its gathering, and a guest disconnect removes them from any
lobby they were in.

---

## 9. NAT traversal and addressing

The server never relays gameplay. It coordinates hole-punching so two consoles
can reach each other directly, using address exchange plus a simultaneous probe.

Two address tiers are built per client in `RegisterEx`
(`secure_connection.register_ex`) and stored as `conn.station_urls`:

| Tier | Source | Example | Used for |
|------|--------|---------|----------|
| LAN | client's own advertised URL, `sid`-stripped, `;RVCID=` added | `prudp:/address=192.168.x.y;port=15986;RVCID=N` | two consoles behind the same router |
| WAN | server-observed `conn.remote` (NAT-mapped IP and port) | `prudp:/address=<pubip>;port=<mappedport>;sid=15;type=3;RVCID=N` | consoles across different NATs |

The WAN port is the observed source port, not the internal 15986. The PS3 uses
one socket for both server traffic and P2P, so the mapping the server observes is
exactly the one peers must punch.

Where addresses go:

- `JoinGathering` section 1 and the browse/quickmatch lists ship the full list
  (both tiers), and the console probes both and uses whichever answers.
- Proto 14 roster-insert notifications ship a single tier per peer.
  `_reachable_url_for` picks LAN when the pair shares a public IP and WAN
  otherwise, because the public IP would only hairpin-fail behind one router.

Probe coordination lives in `protocols/nat.py`. On `RequestProbeInitiation` (m1)
the server resolves the named peer by URL and pushes `InitiateProbe` (m2) to both
sides at once, so each pings the other and both NAT mappings open simultaneously.
For same-NAT pairs it only hands out LAN candidates.

One limitation: only one WAN candidate is synthesized (one observed mapping), and
there is no relay/TURN fallback, so a pair behind two symmetric NATs has nothing
to punch.

---

## 10. Notifications (`protocols/notification.py`, proto 14)

The server is the only party that can tell a client the lobby roster changed or
that stats are ready. These are RMC requests pushed to the client:

```
  [u32 source][u32 type][u32 param1][u32 param2][qString text]
```

The client dispatches on the category (`type / 1000`) and ignores categories it
does not handle:

| Category | Meaning | Subtype (`type % 1000`) |
|---------:|---------|--------------------------|
| 900 | participant roster | 0 = leave (erase), 1 = active, 2 = join (insert; `text` = station URL) |
| 901 | stats processed | updates the client's local career-cash cache |

`param1` is the participant PID (the roster key). `param2` is the gathering id,
which the client uses to gate the event. For a JOIN, `text` carries the new
participant's reachable station URL, so the recipient's roster entry gets a
connection address straight from the server.

Stats notifications are batched. At `CloseParticipation` the server snapshots who
is expected to report. Once every participant has uploaded its m12 (or a 30 s
timeout fires), it pushes a 901 event to all of them at once, so everyone's stats
update together.

---

## 11. Stats subsystem (store-and-serve)

This is where the "server computes nothing" rule plays out.

```
  match end ───>  client aggregates everything locally (cash, kills, bitmasks, maxes)
            ───>  uploads finished career vector in m12 ReportStats
  server    ───>  snapshots it verbatim into the DB, keyed by PID
  next read ───>  m9 ReadStats / leaderboard query reads the DB and serves it back
```

The client owns all the math (sums, ORs, maxes, per-mode bookkeeping) and sends
finished totals. The server stores the uploaded `vec0` blob and hands it straight
back, with no server-side aggregation (`db/career.py`,
`db/migrations/0002_career_stats.sql`).

Wire shape (SparkStats qList): m9 replies and m12 uploads share the same
per-entry layout, `u32 pid + qString name + u32 h2 + vec<f32> x3`. `vec0` is the
122-slot career vector. `vec1` is a reframed view the client reads: the m9 reply
re-emits stored `vec0` at `vec1[slot+5]` for cat 101 and `vec1[slot-56]` for cat
102. `vec2` is unused. `game.py` documents the exact slot maps.

Leaderboards (`leaderboard_query`, m7/m17):

- Every board ranks by cash (`leaderboard_stats.cash DESC`). The mode-stat
  (waves, relics, time, and so on) is a display column from the player's
  best-cash match.
- m17 "Global" returns a top-N page. m7 "AroundSelf" returns a window positioned
  around the requester, which is for visual parity since the client controls its
  own highlight cursor.
- Each m12 stores all six mode-blocks, so modes a player never played sit as
  all-zero rows. Those are excluded from ranking (`cash > 0`).

The DB is the single source of truth; there is no in-memory stats cache. If a
write fails it is logged at ERROR and surfaces on the next read (the old row is
served), rather than being masked.

---

## 12. Persistence (`db/`)

SQLite in WAL mode, opened once as a shared autocommit connection (safe because
the event loop is single-threaded). Migrations in `db/migrations/*.sql` are
applied once each and tracked in a `_migrations` table (`db/connection.py`).

Tables the running server uses:

| Table | Purpose |
|-------|---------|
| `accounts` | PID to psn_id, login timestamps, public-info blob |
| `counters` | sequential `next_pid` allocator |
| `career_stats` | one row per player: packed career `vec0` blob |
| `leaderboard_stats` | one row per (pid, category): cash + mode-stat + map, ranked by cash |

Note that `migrations/0001_init.sql` also defines `stats` (free-form KV),
`gatherings`, and `participants` tables, plus a `next_gathering_id` counter.
These are not currently used: matchmaking state is held in memory
(`state/gatherings.py`), and career stats use the dedicated tables above. They
are schema scaffolding for a possible DB-backed matchmaking or stat model.

---

## 13. State and concurrency model

- Single-threaded asyncio. One event loop drives both UDP listeners, and handlers
  run to completion without preemption. This is why a shared autocommit DB
  connection is safe and why there is no per-request locking on the DB.
- In-memory state lives in `state/`: the `GatheringRegistry` (lobbies and
  participants) and the ID allocators. The registry uses a `threading.Lock`
  defensively, though in practice everything runs on the one loop.
- Persistent state lives in SQLite and is the source of truth for accounts and
  career stats.
- Server-initiated pushes (NAT probes, notifications) are fire-and-forget; the
  server does not track their delivery.

---

## 14. Configuration and deployment (`config.py`)

- `PUBLIC_HOST` is the setting to get right first. It is the address the server
  advertises to clients in the secure station URL, and it must be reachable by
  the console: your LAN IP for home play, or your public IP for internet hosting.
  The `127.0.0.1` default will not work for a real PS3.
- Keys (`ACCESS_KEY`, `RC4_KEY`, `KDF_PASSWORD`) are game-extracted constants and
  are not committed. They load from a gitignored `local_keys.py`, and the server
  refuses to start if any is missing. See `KEYS_README.md` for how to recover
  them from your own copy of the game.
- The DNS shim (`dns_shim.py`) is an optional helper. The console resolves the
  game's back-end hostname through DNS, so pointing the console's DNS at the shim
  lets it answer that hostname with `PUBLIC_HOST` while forwarding all other
  lookups upstream, keeping normal internet and PSN resolution working.

Boot sequence (`server.py::_main_async`): init DB, bind both UDP ports, build a
dispatcher per port and register every protocol on both, wire the `on_close`
gathering-cleanup hooks and the secure-port mutual-auth handler, start the idle
reaper, and run until SIGINT.

---

## 15. Known gaps and signals not acted on

These are either deliberate or pending, and worth knowing when reading the code:

- NAT punch outcome is invisible. There is no success/failure feedback and no
  relay fallback, so two symmetric NATs cannot connect.
- Replies to server pushes are dropped. Probe and notification ACKs are logged
  only.
- In-lobby state is not seen. `UpdateParticipantInfo` (21/39) is accepted but not
  relayed (the game has no receive handler), so loadout and ready ride P2P and
  the server's 16-byte participant `state` stays zero.
- Invites are not wired. Proto 21 m5 is not registered, so `invited_pids` is never
  populated and private slots go unused; only public-slot joins work.
- QuickMatch honors only the `ranked` flag. The other request fields (game_mode,
  max_ping, offset, max_results) are ignored, and only `SearchGatherings` applies
  the full filter.
- Friends, Invitations, and AccountInfo are empty stubs.
- Unranked matches report no stats (no m12), by design.

---

## 16. Glossary

| Term | Meaning |
|------|---------|
| PRUDP | Quazal's reliable-UDP transport. This title uses v0 (hybrid sig/flags/checksum). |
| RMC | Remote Method Call, the request/response layer above PRUDP. |
| Quazal Rendez-Vous | the middleware whose protocols this game and server speak. |
| Gathering | a matchmaking lobby. |
| Station URL | a `prudp:/address=...;port=...` endpoint string used to reach a peer. |
| RVCID | Rendez-Vous connection id, tagged onto station URLs. |
| PID | a player or service principal id (users start at 10000; 1 and 2 are services). |
| SparkStats / SparkGame | the game's stat-blob and lobby-settings container formats. |
| vec0 / vec1 / vec2 | the three float vectors in a SparkStats entry (career, reframed view, unused). |
| m9 / m12 | shorthand for proto 60 method 9 (ReadStats) and 12 (ReportStats). |
| store-and-serve | the persistence model: store what the client uploads, serve it back, compute nothing. |
```
