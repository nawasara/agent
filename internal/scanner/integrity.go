package scanner

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// FileRecord stores the known-good state of a monitored file.
type FileRecord struct {
	Path      string
	SHA256    string
	Size      int64
	ModTime   time.Time
	FirstSeen time.Time
	LastSeen  time.Time
}

// ChangeType describes the kind of file system event detected.
type ChangeType string

const (
	ChangeNew      ChangeType = "new_file"
	ChangeModified ChangeType = "modified"
	ChangeDeleted  ChangeType = "deleted"
)

// FileChange represents a detected change to a monitored file.
type FileChange struct {
	Path       string
	ChangeType ChangeType
	OldHash    string
	NewHash    string
	OldSize    int64
	NewSize    int64
	DetectedAt time.Time
}

// HashDB is a SQLite-backed store of file hashes used for integrity checking.
type HashDB struct {
	db *sql.DB
}

// OpenHashDB opens (or creates) the SQLite hash database at path.
func OpenHashDB(path string) (*HashDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS file_hashes (
			path       TEXT PRIMARY KEY,
			sha256     TEXT NOT NULL,
			size       INTEGER NOT NULL,
			mod_time   INTEGER NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen  INTEGER NOT NULL
		)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &HashDB{db: db}, nil
}

// Close releases the database connection.
func (h *HashDB) Close() error {
	return h.db.Close()
}

// Get retrieves the stored record for path, or returns nil if not found.
func (h *HashDB) Get(path string) (*FileRecord, error) {
	row := h.db.QueryRow(
		`SELECT path, sha256, size, mod_time, first_seen, last_seen FROM file_hashes WHERE path=?`, path)

	var r FileRecord
	var modT, firstS, lastS int64
	if err := row.Scan(&r.Path, &r.SHA256, &r.Size, &modT, &firstS, &lastS); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.ModTime = time.Unix(modT, 0)
	r.FirstSeen = time.Unix(firstS, 0)
	r.LastSeen = time.Unix(lastS, 0)
	return &r, nil
}

// Upsert inserts or updates the hash record for path.
func (h *HashDB) Upsert(r FileRecord) error {
	now := time.Now().Unix()
	_, err := h.db.Exec(`
		INSERT INTO file_hashes(path, sha256, size, mod_time, first_seen, last_seen)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET
		  sha256=excluded.sha256, size=excluded.size,
		  mod_time=excluded.mod_time, last_seen=?`,
		r.Path, r.SHA256, r.Size, r.ModTime.Unix(), now, now, now)
	return err
}

// Delete removes a file record (called when the file is gone).
func (h *HashDB) Delete(path string) error {
	_, err := h.db.Exec(`DELETE FROM file_hashes WHERE path=?`, path)
	return err
}

// AllPaths returns all stored file paths (used to detect deleted files).
func (h *HashDB) AllPaths() ([]string, error) {
	rows, err := h.db.Query(`SELECT path FROM file_hashes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			continue
		}
		paths = append(paths, p)
	}
	return paths, rows.Err()
}

// HashFile computes the SHA256 hash of a file and returns hash + size.
// Returns ("", 0, err) on read failure.
func HashFile(path string) (hash string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// CheckFile compares the current file state against the stored hash record.
// Returns a FileChange if a difference is detected, or nil if the file is
// unchanged.  If the file is new (no record in db), it is stored and a
// ChangeNew is returned.
func (h *HashDB) CheckFile(path string) (*FileChange, error) {
	info, statErr := os.Stat(path)

	stored, err := h.Get(path)
	if err != nil {
		return nil, err
	}

	// File deleted
	if statErr != nil {
		if os.IsNotExist(statErr) && stored != nil {
			if delErr := h.Delete(path); delErr != nil {
				return nil, delErr
			}
			return &FileChange{
				Path:       path,
				ChangeType: ChangeDeleted,
				OldHash:    stored.SHA256,
				OldSize:    stored.Size,
				DetectedAt: time.Now(),
			}, nil
		}
		return nil, statErr
	}

	currentHash, currentSize, err := HashFile(path)
	if err != nil {
		return nil, err
	}

	rec := FileRecord{
		Path:    path,
		SHA256:  currentHash,
		Size:    currentSize,
		ModTime: info.ModTime(),
	}

	// New file — record it and report
	if stored == nil {
		if err := h.Upsert(rec); err != nil {
			return nil, err
		}
		return &FileChange{
			Path:       path,
			ChangeType: ChangeNew,
			NewHash:    currentHash,
			NewSize:    currentSize,
			DetectedAt: time.Now(),
		}, nil
	}

	// Modified file
	if stored.SHA256 != currentHash {
		if err := h.Upsert(rec); err != nil {
			return nil, err
		}
		return &FileChange{
			Path:       path,
			ChangeType: ChangeModified,
			OldHash:    stored.SHA256,
			NewHash:    currentHash,
			OldSize:    stored.Size,
			NewSize:    currentSize,
			DetectedAt: time.Now(),
		}, nil
	}

	// Unchanged — update last_seen
	_ = h.Upsert(rec)
	return nil, nil
}
