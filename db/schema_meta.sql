-- Meta table for storing key-value pairs (user, token, etc)
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
