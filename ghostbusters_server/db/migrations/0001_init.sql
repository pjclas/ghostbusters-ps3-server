-- Ghostbusters PS3 Custom NEX Server — SQLite schema
-- Targets SQLite 3.35+ (for STRICT tables, ON DELETE CASCADE).
-- Run with: sqlite3 server.db < schema.sql

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------
-- PIDs 1-99 are reserved for system services:
--   PID 1 = server's own PID in PRUDP framing (responses from the SECURE service)
--   PID 2 = authentication service identity (target of proto=10 RequestTicket)
-- User PIDs start at 10000 and are allocated sequentially: 10000, 10001, ...
-- keeping them in a distinct range from the system PIDs.
CREATE TABLE accounts (
  pid                          INTEGER PRIMARY KEY,
  psn_id                       TEXT NOT NULL UNIQUE,
  created_at                   INTEGER NOT NULL,
  last_login_at                INTEGER,
  -- 32-byte AccountInfoPublicData blob returned by proto=25 method=9.
  -- Defaults to all-zero; populate real per-account data here to surface it.
  account_info_public_data     BLOB NOT NULL DEFAULT (zeroblob(32))
) STRICT;

INSERT INTO accounts (pid, psn_id, created_at) VALUES
  (1, '_server',         strftime('%s','now')),
  (2, '_authentication', strftime('%s','now'));

-- ---------------------------------------------------------------
-- Stats (free-form KV)
-- ---------------------------------------------------------------
-- Free-form so the server can round-trip whatever the client uploads without
-- committing to a fixed column set. The client's key namespace looks like:
--   {mode}_score, {mode}_money                    (6 modes)
--   weapon_{accuracy|shots|hits|kills}_{weapon}   (7 weapons * 4 metrics = 28)
--   {mode}_{level}_jobs                           (6 modes * 4 levels = 24)
--   stats_version, player_campaign_money, top_earner_campaign
-- Index supports fast world-leaderboard queries (key + value DESC).
CREATE TABLE stats (
  pid          INTEGER NOT NULL REFERENCES accounts(pid) ON DELETE CASCADE,
  key          TEXT    NOT NULL,
  value        INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (pid, key)
) STRICT;

CREATE INDEX stats_leaderboard ON stats(key, value DESC);

-- ---------------------------------------------------------------
-- Gatherings (matchmaking lobbies)
-- ---------------------------------------------------------------
-- gathering_id is allocated sequentially by the server, starting at 10000 to
-- keep server-assigned IDs in a distinct range from the small IDs the client
-- uses internally.
--
-- Every gathering is tied to its owner's session. Cleanup paths:
--   1. Owner explicitly destroys (proto=21 m36 / proto=60 m16) — normal client behavior.
--   2. Owner's PRUDP connection drops (DISCONNECT or PING timeout) — server reaps.
--   3. Optional idle timer (zero participants for >N minutes).
--
-- One active gathering per owner_pid is enforced at the API layer, not with a
-- UNIQUE constraint here (a constraint would error instead of letting
-- CreateGathering replace the prior one — that replace is handled in protocol code).
CREATE TABLE gatherings (
  gathering_id    INTEGER PRIMARY KEY,
  owner_pid       INTEGER NOT NULL REFERENCES accounts(pid),
  type            TEXT    NOT NULL DEFAULT 'SparkGame',
  display_string  TEXT,                  -- e.g. "myguy78_10 1,13,1"
  properties      BLOB,                  -- raw Quazal property-list blob from CreateGathering
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER                -- NULL = no idle timeout
) STRICT;

CREATE INDEX gatherings_by_owner ON gatherings(owner_pid);

-- ---------------------------------------------------------------
-- Participants
-- ---------------------------------------------------------------
-- ON DELETE CASCADE: when a gathering is reaped, its participants vanish too.
-- Participant-change notifications live in protocol code: on join/leave, push a
-- NotificationEvent (proto=14) to the other participants of the gathering.
CREATE TABLE participants (
  gathering_id   INTEGER NOT NULL REFERENCES gatherings(gathering_id) ON DELETE CASCADE,
  pid            INTEGER NOT NULL REFERENCES accounts(pid) ON DELETE CASCADE,
  joined_at      INTEGER NOT NULL,
  PRIMARY KEY (gathering_id, pid)
) STRICT;

CREATE INDEX participants_by_pid ON participants(pid);

-- ---------------------------------------------------------------
-- Counters
-- ---------------------------------------------------------------
-- Sequential ID allocation for PIDs and gathering IDs. Single-row table.
CREATE TABLE counters (
  name   TEXT PRIMARY KEY,
  value  INTEGER NOT NULL
) STRICT;

INSERT INTO counters (name, value) VALUES
  ('next_pid',          10000),
  ('next_gathering_id', 10000);
