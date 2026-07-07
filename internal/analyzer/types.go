package analyzer

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func ScoreToSeverity(score int) Severity {
	switch {
	case score >= 70:
		return SeverityCritical
	case score >= 40:
		return SeverityHigh
	case score >= 20:
		return SeverityMedium
	default:
		return SeverityInfo
	}
}

type Incident struct {
	ID                string
	Type              string
	Severity          Severity
	SourceIP          string
	Score             int
	Correlated        bool
	CorrelatedGroupID string
	Mitre             string // MITRE ATT&CK technique ID
	Evidence          []Evidence
	DetectedAt        time.Time
}

type Evidence struct {
	Timestamp   time.Time `json:"timestamp"`
	Raw         string    `json:"raw"`
	MatchedRule string    `json:"matched_rule"`
}

// Rule defines a detection rule loaded from YAML.
type Rule struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Category    string      `yaml:"category"`
	Severity    string      `yaml:"severity"`
	Score       int         `yaml:"score"`
	Threshold   int         `yaml:"threshold"`
	Mitre       string      `yaml:"mitre"` // MITRE ATT&CK technique ID, e.g. "T1110" or "T1505.003"
	Conditions  Conditions  `yaml:"conditions"`
}

type Conditions struct {
	Source        string   `yaml:"source"` // web_log | ssh_log
	PerIP         bool     `yaml:"per_ip"`
	WindowSeconds int      `yaml:"window_seconds"`
	Method        string   `yaml:"method"`        // POST, GET, etc.
	PathEquals    []string `yaml:"path_equals"`
	PathContains  []string `yaml:"path_contains"`
	PathRegex     []string `yaml:"path_regex"`    // regex matched against full path
	QueryRegex    []string `yaml:"query_regex"`
	UAContains    []string `yaml:"ua_contains"`
	EventType     string   `yaml:"event_type"` // for SSH: "failed" | "root_accepted"
	StatusMin     int      `yaml:"status_min"`
	StatusMax     int      `yaml:"status_max"`
	CountMin      int      `yaml:"count_min"` // threshold count within window
}
