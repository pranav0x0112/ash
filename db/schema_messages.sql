-- Messages table for storing all messages
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    room_id TEXT,
    sender TEXT,
    ts_ms INTEGER,
    body TEXT,
    msgtype TEXT,
    raw_json TEXT
);

-- Links table for storing extracted URLs from messages
CREATE TABLE IF NOT EXISTS links (
    message_id TEXT,
    url TEXT,
    idx INTEGER,
    title TEXT,
    ts_ms INTEGER,
    PRIMARY KEY (message_id, url, idx)
);
