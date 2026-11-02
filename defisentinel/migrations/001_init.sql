-- One row per scan. Sources are not stored, only their SHA-256 per file (files), so a scan can be
-- matched to a commit without keeping proprietary code. findings holds every finding as JSON.
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    label TEXT NOT NULL,
    passed INTEGER NOT NULL,
    fail_on TEXT,
    summary TEXT NOT NULL,
    files TEXT NOT NULL,
    findings TEXT NOT NULL
);
CREATE INDEX scans_created ON scans (created_at);
