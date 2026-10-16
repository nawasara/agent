package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// Code context sent with a signature finding, so staff can judge it in the
// dashboard without SSH — most flags (minified JS, plugins writing their own
// index.php) are dismissed in seconds once the surrounding lines are visible.
//
// Captured at detection time and bounded on purpose. The alternative, a
// dashboard button that asks the agent to read any file on demand, would turn
// the agent into a remote file reader: whoever compromises the dashboard could
// pull every wp-config.php on every server.
const (
	contextLines    = 15   // lines before and after the matching line
	maxLineBytes    = 300  // minified one-liners are cut, not shipped whole
	maxContextBytes = 4096 // hard cap for the whole window
)

// redactors blank credential VALUES before anything leaves the host. A hit in
// wp-config.php or .env must not carry the database password to the dashboard.
var redactors = []struct {
	re   *regexp.Regexp
	repl string
}{
	// define('DB_PASSWORD', '...'), define('AUTH_KEY', '...'), *_SALT, ...
	{regexp.MustCompile(`(?i)(define\s*\(\s*['"](?:DB_PASSWORD|DB_USER|DB_HOST|DB_NAME|[A-Z0-9_]*(?:KEY|SALT|SECRET|TOKEN|PASSWORD|PASS))['"]\s*,\s*)(['"])[^'"]*(['"])`), "${1}${2}***${3}"},
	// .env style: DB_PASSWORD=..., APP_KEY=..., MAIL_PASSWORD=...
	{regexp.MustCompile(`(?im)^(\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|_KEY|TOKEN)[A-Z0-9_]*\s*=\s*).+$`), "${1}***"},
	// 'password' => '...', "api_key": "..."
	{regexp.MustCompile(`(?i)(['"](?:password|passwd|pass|pwd|secret|api_?key|token|db_?pass(?:word)?)['"]\s*(?:=>|:)\s*)(['"])[^'"]*(['"])`), "${1}${2}***${3}"},
	// $db_password = '...';  $token = "...";
	{regexp.MustCompile(`(?i)(\$(?:db_?)?(?:password|passwd|pass|pwd|secret|token|api_?key)\s*=\s*)(['"])[^'"]*(['"])`), "${1}${2}***${3}"},
}

// redact blanks credential values in s.
func redact(s string) string {
	for _, r := range redactors {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// cleanLine replaces control characters and cuts overlong lines.
func cleanLine(line []byte) string {
	cut := false
	if len(line) > maxLineBytes {
		line = line[:maxLineBytes]
		cut = true
	}
	out := make([]byte, 0, len(line))
	for _, b := range line {
		if b < 32 && b != '\t' {
			out = append(out, '.')
		} else {
			out = append(out, b)
		}
	}
	s := strings.ToValidUTF8(string(out), "?")
	if cut {
		s += " …"
	}
	return s
}

// extractContext returns the lines around the match starting at byte offset
// matchStart: the redacted text, the 1-based number of its first line, and the
// 1-based number of the matching line.
func extractContext(data []byte, matchStart int) (string, int, int) {
	if matchStart < 0 || matchStart > len(data) {
		return "", 0, 0
	}
	matchLine := bytes.Count(data[:matchStart], []byte{'\n'}) + 1

	lines := bytes.Split(data, []byte{'\n'})
	first := matchLine - contextLines
	if first < 1 {
		first = 1
	}
	last := matchLine + contextLines
	if last > len(lines) {
		last = len(lines)
	}

	window := make([]string, 0, last-first+1)
	for i := first; i <= last; i++ {
		window = append(window, cleanLine(bytes.TrimRight(lines[i-1], "\r")))
	}

	// Shrink symmetrically until it fits, never dropping the matching line.
	size := func() int {
		n := 0
		for _, l := range window {
			n += len(l) + 1
		}
		return n
	}
	for size() > maxContextBytes && len(window) > 1 {
		idx := matchLine - first // position of the matching line in window
		if idx > len(window)-1-idx {
			window = window[1:]
			first++
		} else {
			window = window[:len(window)-1]
		}
	}

	return redact(strings.Join(window, "\n")), first, matchLine
}
