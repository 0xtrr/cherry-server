-- 0002-remove-url-column.sql
-- Remove the url column from blob_descriptors table since URLs should be constructed dynamically

-- Create a new table without the url column
CREATE TABLE IF NOT EXISTS blob_descriptors_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    type TEXT,
    uploaded INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    UNIQUE(pubkey, sha256)
);

-- Copy data from old table to new table (excluding url column)
INSERT INTO blob_descriptors_new (id, sha256, size, type, uploaded, pubkey)
SELECT id, sha256, size, type, uploaded, pubkey FROM blob_descriptors;

-- Drop the old table
DROP TABLE blob_descriptors;

-- Rename the new table to the original name
ALTER TABLE blob_descriptors_new RENAME TO blob_descriptors;