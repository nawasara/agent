package collector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// CaddyCollector tails Caddy / FrankenPHP access logs, which are line-delimited
// JSON (logger "http.log.access"), not the Combined Log Format that nginx and
// Apache use. Each line is parsed into the same LogEntry the analyzer consumes,
// so detection rules work unchanged.
//
// Behind a reverse proxy (Traefik → Caddy in the Bale stack) request.remote_ip
// is the proxy's address, so the real client IP is taken from X-Forwarded-For
// when present, falling back to remote_ip.
type CaddyCollector struct {
	logPath    string
	vhostGlob  string
	out        chan<- Event
	tailer     *Tailer
	globTailer *GlobTailer
	lineCh     chan string
}

func NewCaddyCollector(logPath string, out chan<- Event) *CaddyCollector {
	lineCh := make(chan string, 1000)
	return &CaddyCollector{logPath: logPath, out: out, lineCh: lineCh, tailer: NewTailer(logPath, lineCh)}
}

// WithVhostGlob enables watching additional access-log files matching the glob.
func (c *CaddyCollector) WithVhostGlob(pattern string) *CaddyCollector {
	c.vhostGlob = pattern
	return c
}

func (c *CaddyCollector) Start() {
	c.tailer.Start()
	if c.vhostGlob != "" {
		c.globTailer = NewGlobTailer(c.vhostGlob, c.lineCh)
		c.globTailer.Start()
	}
	go c.process()
}

func (c *CaddyCollector) Stop() {
	c.tailer.Stop()
	if c.globTailer != nil {
		c.globTailer.Stop()
	}
}

func (c *CaddyCollector) process() {
	for line := range c.lineCh {
		entry := c.parse(strings.TrimSpace(line))
		if entry == nil {
			continue
		}
		select {
		case c.out <- Event{Type: EventLog, Log: entry}:
		default:
		}
	}
}

// caddyAccessLog mirrors the fields of a Caddy access-log line we care about.
// Unknown fields are ignored by encoding/json.
type caddyAccessLog struct {
	Ts      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Msg     string  `json:"msg"`
	Status  int     `json:"status"`
	Size    int     `json:"size"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

func (c *CaddyCollector) parse(line string) *LogEntry {
	if line == "" || line[0] != '{' {
		return nil // not JSON — skip (e.g. Caddy startup/non-access lines)
	}

	var log caddyAccessLog
	if err := json.Unmarshal([]byte(line), &log); err != nil {
		return nil
	}

	// Only access-log entries carry request data. Other Caddy loggers
	// (tls, admin, etc.) share the file when logging is global — skip them.
	if log.Request.Method == "" && log.Request.URI == "" {
		return nil
	}

	ts := time.Now()
	if log.Ts > 0 {
		sec := int64(log.Ts)
		nsec := int64((log.Ts - float64(sec)) * 1e9)
		ts = time.Unix(sec, nsec)
	}

	// Real client IP: first X-Forwarded-For entry (client-most), else remote_ip.
	ip := clientIP(log.Request.Headers, log.Request.RemoteIP)

	path := log.Request.URI
	query := ""
	if u, err := url.Parse(log.Request.URI); err == nil {
		path = u.Path
		query = u.RawQuery
	}

	return &LogEntry{
		Timestamp:  ts,
		SourceIP:   ip,
		Method:     log.Request.Method,
		Path:       path,
		Query:      query,
		StatusCode: log.Status,
		BytesSent:  log.Size,
		Referer:    firstHeader(log.Request.Headers, "Referer"),
		UserAgent:  firstHeader(log.Request.Headers, "User-Agent"),
		Source:     "caddy",
		Raw:        fmt.Sprintf("%s %s", log.Request.Method, log.Request.URI),
	}
}

// clientIP returns the real client IP: the left-most X-Forwarded-For value
// (the original client, before any proxy hops), falling back to remote_ip.
func clientIP(headers map[string][]string, remoteIP string) string {
	if xff := firstHeader(headers, "X-Forwarded-For"); xff != "" {
		// XFF may be "client, proxy1, proxy2" — the first is the real client.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	return remoteIP
}

// firstHeader does a case-insensitive lookup returning the first value.
func firstHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
