package collector

import "time"

type LogEntry struct {
	Timestamp  time.Time
	SourceIP   string
	Method     string
	Path       string
	Query      string
	StatusCode int
	BytesSent  int
	UserAgent  string
	Referer    string
	Source     string // "nginx" | "apache"
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
