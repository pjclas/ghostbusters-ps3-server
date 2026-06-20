-- ---------------------------------------------------------------
-- Career stats + leaderboard persistence  (REPLACE store-and-serve)
-- ---------------------------------------------------------------
-- The client computes every career total / bitmask / max itself and uploads
-- the finished value in the m=12 ReportStats. The server's job is purely to
-- snapshot the upload and serve it straight back as the m=9 baseline — there is
-- NO server-side aggregation. So career storage is just "store the uploaded
-- vec0 blob per PID, hand it back".

-- One row per player: the full career vec0 (packed little-endian f32[]), served
-- back framed for cat=101 (slot+5) and cat=102 (slot-56).
CREATE TABLE career_stats (
  pid         INTEGER PRIMARY KEY REFERENCES accounts(pid) ON DELETE CASCADE,
  vec0        BLOB    NOT NULL,            -- packed <f32[]  (career frame, len 122)
  updated_at  INTEGER NOT NULL
) STRICT;

-- Per-category leaderboard baseline. All boards rank by cash; the mode-stat
-- (waves / relics / completion-time / slimer-count / ...) is a display column
-- carrying the stat from the player's best-cash match. One row per (pid,cat),
-- sourced from the m=12 vec1 mode-blocks, served as the cat=20x/30x own-baseline
-- (so the host knows its existing high score) and ranked across players for the
-- m=7 / m=17 board list.
CREATE TABLE leaderboard_stats (
  pid         INTEGER NOT NULL REFERENCES accounts(pid) ON DELETE CASCADE,
  category    INTEGER NOT NULL,            -- 201-205 campaign, 301-307 instant
  cash        REAL    NOT NULL DEFAULT 0,
  mode_stat   REAL    NOT NULL DEFAULT 0,
  map_id      INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (pid, category)
) STRICT;

CREATE INDEX leaderboard_by_cat ON leaderboard_stats(category, cash DESC);
