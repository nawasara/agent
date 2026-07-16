package collector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TraefikCollector tails Traefik access logs in JSON format. Traefik is the edge
// reverse proxy in the Bale stack (Traefik -> app container on rakaca-network),
// so it sees every public request first and is the right place to detect attacks
// against apps that sit behind it (e.g. bale-cms / dindik-profile), which expose
// only an internal container port and have no host-level web-server log of their
// own.
//
// Traefik's JSON access log is line-delimited JSON with FLAT keys (unlike Caddy's
// nested "request" object), e.g.:
//
//	{"ClientHost":"10.0.0.1","RequestMethod":"POST","RequestPath":"/wp-login.php?x=1",
//	 "RequestHost":"bale.test","DownstreamStatus":403,"DownstreamContentSize":128,
//	 "request_User-Agent":"sqlmap/1.5","request_X-Forwarded-For":"203.0.113.9, 10.0.0.1",
//	 "StartUTC":"2026-07-16T02:00:00Z"}
//
// The real client IP is taken from request_X-Forwarded-For (client-most entry)
// when present — Traefik behind Cloudflare/another proxy has ClientHost set to
// the upstream hop — falling back to ClientHost.
type TraefikCollector struct {
	logPath    string
	vhostGlob  string
	out        chan<- Event
	tailer     *Tailer
	globTailer *GlobTailer
	lineCh     chan Line
}

func NewTraefikCollector(logPath string, out chan<- Event) *TraefikCollector {
	lineCh := make(chan Line, 1000)
	return &TraefikCollector{logPath: logPath, out: out, lineCh: lineCh, tailer: NewTailer(logPath, lineCh)}
}

// WithVhostGlob enables watching additional access-log files matching the glob
// (Traefik can write per-router/per-service logs when configured to).
func (c *TraefikCollector) WithVhostGlob(pattern string) *TraefikCollector {
	c.vhostGlob = pattern
	return c
}

func (c *TraefikCollector) Start() {
	c.tailer.Start()
	if c.vhostGlob != "" {
		c.globTailer = NewGlobTailer(c.vhostGlob, c.lineCh)
		c.globTailer.Start()
	}
	go c.process()
}

func (c *TraefikCollector) Stop() {
	c.tailer.Stop()
	if c.globTailer != nil {
		c.globTailer.Stop()
	}
}

func (c *TraefikCollector) process() {
	for line := range c.lineCh {
		entry := c.parse(strings.TrimSpace(line.Text))
		if entry == nil {
			continue
		}
		select {
		case c.out <- Event{Type: EventLog, Log: entry}:
		default:
		}
	}
}

// traefikAccessLog mirrors the flat fields of a Traefik JSON access-log line we
// care about. Unknown fields are ignored by encoding/json. Traefik prefixes
// captured request headers with "request_" and response headers with
// "downstream_"; we read the request headers.
type traefikAccessLog struct {
	ClientHost            string `json:"ClientHost"`
	RequestMethod         string `json:"RequestMethod"`
	RequestPath           string `json:"RequestPath"` // includes query string
	RequestHost           string `json:"RequestHost"`
	DownstreamStatus      int    `json:"DownstreamStatus"`
	DownstreamContentSize int    `json:"DownstreamContentSize"`
	StartUTC              string `json:"StartUTC"`
	Time                  string `json:"time"` // alternate timestamp key in some setups
	XForwardedFor         string `json:"request_X-Forwarded-For"`
	UserAgent             string `json:"request_User-Agent"`
	Referer               string `json:"request_Referer"`
}

func (c *TraefikCollector) parse(line string) *LogEntry {
	if line == "" || line[0] != '{' {
		return nil // not JSON — skip (e.g. Traefik startup / CLF-format lines)
	}

	var log traefikAccessLog
	if err := json.Unmarshal([]byte(line), &log); err != nil {
		return nil
	}

	// Only access-log entries carry request data. Traefik's app/error logger can
	// share a file in some configs — skip anything without a method/path.
	if log.RequestMethod == "" && log.RequestPath == "" {
		return nil
	}

	ts := c.parseTime(log)

	// Real client IP: first X-Forwarded-For value (client-most), else ClientHost.
	ip := traefikClientIP(log.XForwardedFor, log.ClientHost)

	// RequestPath carries "/path?query" — split it the same way Caddy does.
	path := log.RequestPath
	query := ""
	if u, err := url.Parse(log.RequestPath); err == nil {
		path = u.Path
		query = u.RawQuery
	}

	return &LogEntry{
		Timestamp:  ts,
		SourceIP:   ip,
		Host:       log.RequestHost,
		Method:     log.RequestMethod,
		Path:       path,
		Query:      query,
		StatusCode: log.DownstreamStatus,
		BytesSent:  log.DownstreamContentSize,
		Referer:    log.Referer,
		UserAgent:  log.UserAgent,
		Source:     "traefik",
		Raw:        fmt.Sprintf("%s %s", log.RequestMethod, log.RequestPath),
	}
}

// parseTime reads Traefik's RFC3339 timestamp (StartUTC, or the "time" key),
// falling back to now when neither is present or parseable.
func (c *TraefikCollector) parseTime(log traefikAccessLog) time.Time {
	for _, raw := range []string{log.StartUTC, log.Time} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t
		}
	}
	return time.Now()
}

// traefikClientIP returns the real client IP: the left-most X-Forwarded-For value
// (the original client, before any proxy hops), falling back to ClientHost.
// Traefik's XFF is a plain "client, proxy1, proxy2" string.
func traefikClientIP(xff, clientHost string) string {
	if xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	return clientHost
}
