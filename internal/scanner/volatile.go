package scanner

import "strings"

// defaultVolatilePaths are path substrings whose files change on their own —
// page caches, logs, sessions, compiled templates. A hash change there is the
// application working, not an intrusion.
//
// Measured on alpine (WHM) in October 2026: 29,150 of 29,856 open findings were
// file_integrity, almost all WP Super Cache pages and per-day log files. The
// 131 judol pages the scanner had correctly found were buried among them and
// nobody noticed for three months.
//
// Only the INTEGRITY check skips these. The signature scan still reads every
// file, so spam or a webshell planted inside a cache dir is still reported.
var defaultVolatilePaths = []string{
	"/wp-content/cache/",
	"/wp-content/litespeed/",
	"/wp-content/et-cache/",
	"/wp-content/uploads/cache/",
	"/wp-content/w3tc-config/",
	"/storage/framework/",
	"/storage/logs/",
	"/bootstrap/cache/",
	"/application/logs/",
	"/application/cache/",
	"/application/user/logs/",
	"/writable/cache/",
	"/writable/logs/",
	"/writable/session/",
	"/tmp/",
	"/cache/",
	"/logs/",
}

// isVolatilePath reports whether the integrity check should skip path.
func isVolatilePath(path string, extra []string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))

	for _, p := range defaultVolatilePaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	for _, p := range extra {
		if p != "" && strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}

	// Per-day log files written as PHP to stop them being served raw
	// (CodeIgniter: log-2026-10-16.php).
	base := lower[strings.LastIndex(lower, "/")+1:]
	if strings.HasPrefix(base, "log-") && strings.HasSuffix(base, ".php") {
		return true
	}

	return false
}
