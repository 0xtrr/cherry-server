-- 0001-schema.sql
CREATE TABLE IF NOT EXISTS blob_descriptors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    type TEXT,
    uploaded INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    UNIQUE(pubkey, sha256)
);

-- Track the number of references (uploads) to each file
CREATE TABLE IF NOT EXISTS file_references (
    sha256 TEXT PRIMARY KEY,
    reference_count INTEGER NOT NULL
);