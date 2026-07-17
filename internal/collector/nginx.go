package collector

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Combined log format: $remote_addr - $remote_user [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"
var nginxPattern = regexp.MustCompile(
	`^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"`,
)

// vhost_combined format: a leading $host before the standard combined fields —
// e.g. log_format vhost '$host $remote_addr - $remote_user [$time_local] ...'.
// Servers with one shared access.log can opt into this to record the target
// domain per line (the Combined Log Format alone carries no host). $host is
// group 1; the rest mirror nginxPattern shifted by one.
//
// The 2nd field is constrained to an IPv4/IPv6/`-` (the $remote_addr) so this
// does NOT ambiguously match a standard Combined line, whose 2nd field is the
// literal "-" ($remote_user placeholder) — there the address is field 1.
var nginxVhostPattern = regexp.MustCompile(
	`^(\S+) ([0-9a-fA-F.:]+) - \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"`,
)

const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

type NginxCollector struct {
	logPath    string
	vhostGlob  string // optional glob for vhost logs
	source     string // "nginx" | "apache"
	out        chan<- Event
	tailer     *Tailer
	globTailer *GlobTailer
	lineCh     chan Line
}

func NewNginxCollector(logPath string, out chan<- Event) *NginxCollector {
	// Large buffer: on WHM/cPanel the vhost glob can attach hundreds of per-domain
	// tailers feeding this one channel; a small buffer would drop lines (incl.
	// attacks) under load. process() reads fast, so this is just burst headroom.
	lineCh := make(chan Line, 20000)
	return &NginxCollector{logPath: logPath, source: "nginx", out: out, lineCh: lineCh, tailer: NewTailer(logPath, lineCh)}
}

// WithVhostGlob enables watching additional vhost log files matching the glob pattern.
func (c *NginxCollector) WithVhostGlob(pattern string) *NginxCollector {
	c.vhostGlob = pattern
	return c
}

func (c *NginxCollector) Start() {
	c.tailer.Start()
	if c.vhostGlob != "" {
		c.globTailer = NewGlobTailer(c.vhostGlob, c.lineCh)
		c.globTailer.Start()
	}
	go c.process()
}

func (c *NginxCollector) Stop() {
	c.tailer.Stop()
	if c.globTailer != nil {
		c.globTailer.Stop()
	}
}

func (c *NginxCollector) process() {
	for line := range c.lineCh {
		entry := c.parse(strings.TrimSpace(line.Text), line.Source)
		if entry == nil {
			continue
		}
		select {
		case c.out <- Event{Type: EventLog, Log: entry}:
		default:
		}
	}
}

func (c *NginxCollector) parse(line, source string) *LogEntry {
	// Try the vhost_combined format first ($host leads the line). If it matches,
	// the host comes straight from the log line — this is how non-WHM single-log
	// setups report the target domain. Otherwise fall back to standard Combined
	// Log Format, deriving host from the (per-domain) filename.
	var (
		host                = ""
		ipIdx               = 1
		tsIdx               = 2
		methodIdx, pathIdx  = 3, 4
		statusIdx, bytesIdx = 5, 6
		refIdx, uaIdx       = 7, 8
	)
	m := nginxVhostPattern.FindStringSubmatch(line)
	if m != nil {
		// vhost_combined: group 1 = $host, remaining fields shifted by one.
		host = m[1]
		ipIdx, tsIdx = 2, 3
		methodIdx, pathIdx = 4, 5
		statusIdx, bytesIdx = 6, 7
		refIdx, uaIdx = 8, 9
	} else {
		m = nginxPattern.FindStringSubmatch(line)
		if m == nil {
			return nil
		}
		host = hostFromLogPath(source)
	}

	ts, err := time.Parse(nginxTimeLayout, m[tsIdx])
	if err != nil {
		ts = time.Now()
	}

	status, _ := strconv.Atoi(m[statusIdx])
	bytes, _ := strconv.Atoi(m[bytesIdx])

	rawPath := m[pathIdx]
	parsedURL, _ := url.Parse(rawPath)
	path := rawPath
	query := ""
	if parsedURL != nil {
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}

	// A leading "-" or "_" for $host means nginx had no Host header — treat as unknown.
	if host == "-" || host == "_" {
		host = ""
	}

	return &LogEntry{
		Timestamp:  ts,
		SourceIP:   m[ipIdx],
		Host:       host,
		Method:     m[methodIdx],
		Path:       path,
		Query:      query,
		StatusCode: status,
		BytesSent:  bytes,
		Referer:    m[refIdx],
		UserAgent:  m[uaIdx],
		Source:     c.source,
		Raw:        fmt.Sprintf("%s %s", m[methodIdx], rawPath),
	}
}

// hostFromLogPath derives the vhost/domain from a per-domain log filename, the
// convention on WHM/cPanel (/var/log/apache2/domlogs/<domain>) and per-site
// nginx logs (/var/log/nginx/<domain>_access.log). Combined Log Format lines
// carry no Host, so the filename is the only signal. Returns "" for the generic
// combined log (access.log) where the domain is unknown.
func hostFromLogPath(path string) string {
	if path == "" {
		return ""
	}
	base := filepath.Base(path)

	// Strip common access-log suffixes to recover the bare domain. cPanel/WHM
	// writes <domain>, <domain>-ssl_log and <domain>-bytes_log per site; nginx
	// per-site logs use <domain>_access.log etc. Longest/most-specific first so
	// "-bytes_log" isn't left as "-bytes" by an earlier "_log" match.
	for _, suf := range []string{
		"-bytes_log", "_bytes_log", "-bytes", "_bytes",
		"-ssl_log", "_ssl_log", ".ssl_log",
		"_access.log", "-access.log", ".access.log",
		"_access_log", "-access_log",
		"_access", "-access",
		".log", "_log",
	} {
		if strings.HasSuffix(base, suf) {
			base = strings.TrimSuffix(base, suf)
			break
		}
	}

	// Generic combined logs carry no domain — don't invent one.
	switch base {
	case "access", "other_vhosts_access", "nginx", "apache2", "":
		return ""
	}

	// A domain must look like one (has a dot). Guards against odd filenames.
	if !strings.Contains(base, ".") {
		return ""
	}
	return base
}
