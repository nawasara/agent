package scanner

import "strings"

// defaultVolatilePaths are path substrings whose files change on their own —
// page caches, logs, sessions, compiled templates. A hash change there is the
// application working, not an intrusion.
//
// Measured on alpine (WHM), 16 Oct 2026: of 29,263 open integrity findings only
// 1,818 were caches/logs. Most (27,445) were WordPress core and plugin files
// changed by updates; those are NOT listed here, because wp-includes and
// plugins are exactly where backdoors are planted. Separating updates from
// tampering needs WordPress checksums, not a path list.
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
