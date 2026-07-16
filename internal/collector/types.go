package collector

import "time"

// Line is a raw log line plus the file it was read from. The source path lets a
// collector derive the vhost/domain when the web server writes per-domain logs
// (e.g. WHM/cPanel domlogs: /var/log/apache2/domlogs/<domain>), where the Host
// is the filename rather than a field in the line.
type Line struct {
	Text   string
	Source string // absolute path of the log file this line came from
}

type LogEntry struct {
	Timestamp  time.Time
	SourceIP   string
	Host       string // target vhost/domain (Host header). Empty if unknown.
	Method     string
	Path       string
	Query      string
	StatusCode int
	BytesSent  int
	UserAgent  string
	Referer    string
	Source     string // "nginx" | "apache" | "caddy" | "traefik"
	Raw        string
}

type SSHEvent struct {
	Timestamp time.Time
	SourceIP  string
	User      string
	EventType string // "failed" | "accepted" | "invalid_user" | "root_accepted"
	Port      int
	Raw       string
}

type SystemMetrics struct {
	Timestamp   time.Time
	CPUPercent  float64
	MemUsedMB   uint64
	MemTotalMB  uint64
	DiskUsedPct float64
	LoadAvg1    float64
	LoadAvg5    float64
}

// Event wraps all collector outputs into a single channel type.
type Event struct {
	Type    EventType
	Log     *LogEntry
	SSH     *SSHEvent
	Metrics *SystemMetrics
}

type EventType int

const (
	EventLog EventType = iota
	EventSSH
	EventMetrics
)
