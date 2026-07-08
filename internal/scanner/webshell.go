package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// ScanResult represents a single suspicious file finding.
type ScanResult struct {
	Path        string
	SignatureID string
	SigName     string
	Category    string // webshell | backdoor | exploit | suspicious
	Severity    string // critical | high | medium
	Score       int
	Description string
	Mitre       string // MITRE ATT&CK technique ID
	MatchedLine string // first matching snippet (truncated to 120 chars)
}

// maxScanBytes is the read limit per file — large files are read in chunks up
// to this limit to cap memory usage.  Most PHP webshells are injected near the
// top of a file, so 512 KB is sufficient.
const maxScanBytes = 512 * 1024

// allowedExtensions lists PHP-family file extensions we scan for malicious code.
// .html/.htm are included because SEO-spam pages (pharma/gambling) are often
// dropped as static HTML files outside WordPress, not as PHP or DB posts.
var allowedExtensions = map[string]bool{
	".php":    true,
	".php3":   true,
	".php4":   true,
	".php5":   true,
	".php7":   true,
	".phtml":  true,
	".phar":   true,
	".php-s":  true,
	".shtml":  true,
	".html":   true,
	".htm":    true,
	".js": true, // sometimes used for server-side injected loaders
}

// WebshellScanner scans files against the signature database.
type WebshellScanner struct {
	db *SignatureDB
}

// NewWebshellScanner creates a scanner backed by the given signature database.
func NewWebshellScanner(db *SignatureDB) *WebshellScanner {
	return &WebshellScanner{db: db}
}

// ScanFile scans a single file and returns all matches.
// Returns nil if no match is found.
func (s *WebshellScanner) ScanFile(path string) ([]ScanResult, error) {
	if !shouldScan(path) {
		return nil, nil
	}

	data, err := readLimited(path, maxScanBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var results []ScanResult
	seen := map[string]bool{}

	for _, cs := range s.db.compiled {
		for _, re := range cs.regexps {
			if re.Match(data) {
				if seen[cs.sig.ID] {
					break // one result per signature per file
				}
				seen[cs.sig.ID] = true
				loc := re.re.Find(data)
				snippet := sanitize(loc)
				results = append(results, ScanResult{
					Path:        path,
					SignatureID: cs.sig.ID,
					SigName:     cs.sig.Name,
					Category:    cs.sig.Category,
					Severity:    cs.sig.Severity,
					Score:       cs.sig.Score,
					Description: cs.sig.Description,
					Mitre:       cs.sig.Mitre,
					MatchedLine: snippet,
				})
				break // one match per signature is enough
			}
		}
	}

	return results, nil
}

// shouldScan returns true if the file should be scanned based on extension or
// base name, and is not under a skip path (vendor, node_modules, .git).
func shouldScan(path string) bool {
	lower := strings.ToLower(path)
	for _, skip := range []string{"/vendor/", "/node_modules/", "/.git/", "/.svn/"} {
		if strings.Contains(lower, skip) {
			return false
		}
	}
	base := strings.ToLower(filepath.Base(path))
	// Special filenames without a typical extension
	if base == ".htaccess" || base == ".user.ini" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return allowedExtensions[ext]
}

// readLimited reads up to limit bytes from a file.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, limit)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// sanitize extracts a printable snippet from raw regex match bytes,
// truncated to 120 characters and with control chars replaced.
func sanitize(raw []byte) string {
	if len(raw) > 120 {
		raw = raw[:120]
	}
	out := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b < 32 && b != '\t' && b != '\n' {
			out = append(out, '.')
		} else {
			out = append(out, b)
		}
	}
	// collapse newlines for the snippet
	return strings.TrimSpace(strings.ReplaceAll(string(out), "\n", " | "))
}
