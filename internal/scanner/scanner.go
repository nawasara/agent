package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nawasara/agent/internal/analyzer"
	"github.com/nawasara/agent/internal/config"
)

// Scanner is the Phase 3 file scanner.  It runs two loops in parallel:
//  1. Periodic full scan of web dirs for webshells/backdoors (signature scan).
//  2. Integrity watch on critical files (hash comparison on every scan cycle).
//
// Findings are pushed to Dashboard via POST /api/agent/scan-findings AND emitted
// as analyzer.Incident on the shared incidentCh so they appear in the findings
// table and trigger alerts.
type Scanner struct {
	cfg       *config.Config
	db        *SignatureDB
	hashDB    *HashDB
	ws        *WebshellScanner
	incidentC chan<- analyzer.Incident
	client    *http.Client
}

// New creates a Scanner.  Call Run(ctx) in a goroutine.
func New(cfg *config.Config, incidentC chan<- analyzer.Incident) (*Scanner, error) {
	sigDB, err := LoadSignatureDB(cfg.Scanner.SignaturesDB)
	if err != nil {
		return nil, fmt.Errorf("load signature db: %w", err)
	}
	log.Printf("[scanner] loaded signature db version=%s webshells=%d backdoors=%d exploits=%d",
		sigDB.Version, len(sigDB.Webshells), len(sigDB.Backdoors), len(sigDB.Exploits))

	hashDB, err := OpenHashDB(cfg.Scanner.HashDB)
	if err != nil {
		return nil, fmt.Errorf("open hash db: %w", err)
	}

	return &Scanner{
		cfg:       cfg,
		db:        sigDB,
		hashDB:    hashDB,
		ws:        NewWebshellScanner(sigDB),
		incidentC: incidentC,
		client:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Run starts the periodic scan loop.  Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	log.Printf("[scanner] started — interval=%s dirs=%v watchPaths=%d",
		s.cfg.Scanner.ScanInterval, s.cfg.Scanner.WebDirs, len(s.cfg.Scanner.WatchPaths))

	// Run an initial scan shortly after startup so we baseline the hash DB.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	s.runScan(ctx)

	ticker := time.NewTicker(s.cfg.Scanner.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.hashDB.Close()
			return
		case <-ticker.C:
			s.runScan(ctx)
		}
	}
}

func (s *Scanner) runScan(ctx context.Context) {
	start := time.Now()
	log.Printf("[scanner] scan started")

	var (
		filesScanned int
		findingsTotal int
	)

	// 1. Signature scan of web directories
	for _, dir := range s.cfg.Scanner.WebDirs {
		// Expand globs (e.g. /home/*/public_html)
		matches, err := filepath.Glob(dir)
		if err != nil || len(matches) == 0 {
			// Not a glob — treat as plain path
			matches = []string{dir}
		}
		for _, expanded := range matches {
			scanned, findings := s.scanDir(ctx, expanded)
			filesScanned += scanned
			findingsTotal += findings
		}
	}

	// 2. Integrity check on watch paths (critical files)
	for _, watchPath := range s.cfg.Scanner.WatchPaths {
		if ctx.Err() != nil {
			break
		}
		s.checkIntegrity(watchPath)
	}

	log.Printf("[scanner] scan done — files=%d findings=%d elapsed=%s",
		filesScanned, findingsTotal, time.Since(start).Round(time.Millisecond))
}

// scanDir walks dir recursively and scans each file.  Returns file count and
// finding count.  Respects ctx cancellation between files.
func (s *Scanner) scanDir(ctx context.Context, dir string) (files, findings int) {
	if _, err := os.Stat(dir); err != nil {
		return 0, 0
	}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if info.IsDir() {
			// Skip hidden dirs and known-safe subdirectories
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldScan(path) {
			return nil
		}

		files++

		// --- Signature scan ---
		results, scanErr := s.ws.ScanFile(path)
		if scanErr != nil {
			return nil
		}
		for _, r := range results {
			findings++
			s.emitFinding(r, info)
		}

		// --- Integrity check for web files ---
		change, intErr := s.hashDB.CheckFile(path)
		if intErr != nil || change == nil {
			return nil
		}
		// Only flag modifications to existing files as incidents; new files in
		// web dirs are handled during the signature scan pass above.
		if change.ChangeType == ChangeModified {
			s.emitIntegrityChange(change)
		}

		return nil
	})
	return files, findings
}

// checkIntegrity checks a single watch path (critical file) for changes.
func (s *Scanner) checkIntegrity(path string) {
	change, err := s.hashDB.CheckFile(path)
	if err != nil || change == nil {
		return
	}
	s.emitIntegrityChange(change)
}

// emitFinding sends a webshell/backdoor finding to the incidentCh and to the
// Dashboard scan-findings endpoint.
func (s *Scanner) emitFinding(r ScanResult, info os.FileInfo) {
	log.Printf("[scanner] FINDING %s %s (%s) in %s", r.Severity, r.SigName, r.SignatureID, r.Path)

	inc := analyzer.Incident{
		ID:       deterministicID(r.Path, r.SignatureID),
		Type:     "file_scan_" + r.Category,
		Severity: analyzer.Severity(r.Severity),
		SourceIP: "", // filesystem finding, no source IP
		Score:    r.Score,
		Evidence: []analyzer.Evidence{
			{
				Timestamp:   time.Now(),
				Raw:         fmt.Sprintf("[%s] %s: %s", r.SignatureID, r.Path, r.MatchedLine),
				MatchedRule: r.SignatureID,
			},
		},
		DetectedAt: time.Now(),
	}
	select {
	case s.incidentC <- inc:
	default:
	}

	// Also push structured finding to dedicated endpoint
	payload := map[string]any{
		"finding_id":      inc.ID,
		"path":            r.Path,
		"signature_id":    r.SignatureID,
		"sig_name":        r.SigName,
		"category":        r.Category,
		"severity":        r.Severity,
		"score":           r.Score,
		"description":     r.Description,
		"mitre_technique": r.Mitre,
		"matched_line":    r.MatchedLine,
		"file_size":       info.Size(),
		"file_mtime":      info.ModTime().Unix(),
		"detected_at":     time.Now().Unix(),
	}
	s.pushFinding(payload)
}

// emitIntegrityChange reports a critical-file modification.
func (s *Scanner) emitIntegrityChange(change *FileChange) {
	log.Printf("[scanner] INTEGRITY %s path=%s old=%s new=%s",
		change.ChangeType, change.Path, change.OldHash[:min8(len(change.OldHash))], change.NewHash[:min8(len(change.NewHash))])

	severity := analyzer.SeverityHigh
	score := 60
	if isCriticalPath(change.Path) {
		severity = analyzer.SeverityCritical
		score = 80
	}

	inc := analyzer.Incident{
		ID:       deterministicID(change.Path, string(change.ChangeType), change.NewHash),
		Type:     "file_integrity_" + string(change.ChangeType),
		Severity: severity,
		SourceIP: "",
		Score:    score,
		Evidence: []analyzer.Evidence{
			{
				Timestamp:   change.DetectedAt,
				Raw:         fmt.Sprintf("%s: %s (old=%s new=%s)", change.ChangeType, change.Path, change.OldHash, change.NewHash),
				MatchedRule: "file_integrity",
			},
		},
		DetectedAt: change.DetectedAt,
	}
	select {
	case s.incidentC <- inc:
	default:
	}

	payload := map[string]any{
		"finding_id":      inc.ID,
		"path":            change.Path,
		"signature_id":    "file_integrity",
		"sig_name":        "File Integrity Change",
		"category":        "integrity",
		"severity":        string(severity),
		"score":           score,
		"description":     fmt.Sprintf("File %s: %s", change.ChangeType, change.Path),
		"mitre_technique": "T1565.001",
		"matched_line":    fmt.Sprintf("old=%s new=%s", change.OldHash, change.NewHash),
		"file_size":       change.NewSize,
		"detected_at":     change.DetectedAt.Unix(),
	}
	s.pushFinding(payload)
}

// pushFinding POSTs a structured finding to the Dashboard.
func (s *Scanner) pushFinding(payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := strings.TrimRight(s.cfg.DashboardURL, "/") + "/api/agent/scan-findings"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", s.cfg.APIKey)
	req.Header.Set("X-Agent-Id", s.cfg.AgentID)

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[scanner] pushFinding failed: %v", err)
		return
	}
	resp.Body.Close()
}

// isCriticalPath returns true for files that should be treated as critical even
// when found outside the explicit watch_paths list.
func isCriticalPath(path string) bool {
	base := filepath.Base(path)
	for _, name := range []string{".env", ".env.production", ".env.local", "composer.json", "composer.lock", "wp-config.php", "config.php"} {
		if strings.EqualFold(base, name) {
			return true
		}
	}
	return false
}

// deterministicID derives a stable finding ID from its identity parts so the
// same file + signature reported across scan cycles reuses the same ID. The
// Dashboard dedupes by this ID and bumps last_seen_at instead of inserting a
// duplicate row every cycle.
func deterministicID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "sc_" + hex.EncodeToString(h[:8])
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}
