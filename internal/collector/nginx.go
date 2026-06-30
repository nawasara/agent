package collector

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Combined log format: $remote_addr - $remote_user [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"
var nginxPattern = regexp.MustCompile(
	`^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"`,
)

const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

type NginxCollector struct {
	logPath string
	source  string // "nginx" | "apache"
	out     chan<- Event
	tailer  *Tailer
	lineCh  chan string
}

func NewNginxCollector(logPath string, out chan<- Event) *NginxCollector {
	lineCh := make(chan string, 1000)
	return &NginxCollector{logPath: logPath, source: "nginx", out: out, lineCh: lineCh, tailer: NewTailer(logPath, lineCh)}
}

func (c *NginxCollector) Start() {
	c.tailer.Start()
	go c.process()
}

func (c *NginxCollector) Stop() {
	c.tailer.Stop()
}

func (c *NginxCollector) process() {
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

func (c *NginxCollector) parse(line string) *LogEntry {
	m := nginxPattern.FindStringSubmatch(line)
	if m == nil {
		return nil
	}

	ts, err := time.Parse(nginxTimeLayout, m[2])
	if err != nil {
		ts = time.Now()
	}

	status, _ := strconv.Atoi(m[5])
	bytes, _ := strconv.Atoi(m[6])

	rawPath := m[4]
	parsedURL, _ := url.Parse(rawPath)
	path := rawPath
	query := ""
	if parsedURL != nil {
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}

	return &LogEntry{
		Timestamp:  ts,
		SourceIP:   m[1],
		Method:     m[3],
		Path:       path,
		Query:      query,
		StatusCode: status,
		BytesSent:  bytes,
		Referer:    m[7],
		UserAgent:  m[8],
		Source:     c.source,
		Raw:        fmt.Sprintf("%s %s", m[3], rawPath),
	}
}
