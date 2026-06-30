package analyzer

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nawasara/agent/internal/collector"
)

// Engine matches collector events against rules and emits Incidents.
type Engine struct {
	rules     []Rule
	window    *IPWindow
	incidentC chan<- Incident
}

func NewEngine(rules []Rule, correlationWindow time.Duration, incidentC chan<- Incident) *Engine {
	return &Engine{
		rules:     rules,
		window:    NewIPWindow(correlationWindow),
		incidentC: incidentC,
	}
}

func (e *Engine) ProcessLog(entry *collector.LogEntry) {
	for _, rule := range e.rules {
		if rule.Conditions.Source != "web_log" {
			continue
		}
		if !e.matchLog(rule, entry) {
			continue
		}
		ev := Evidence{Timestamp: entry.Timestamp, Raw: entry.Raw, MatchedRule: rule.ID}
		threshold := rule.Threshold
		if threshold == 0 {
			threshold = 20
		}
		total, evList, types := e.window.Add(entry.SourceIP, rule.Score, ev, rule.Category)
		if total >= threshold {
			e.emit(entry.SourceIP, rule, evList, types)
			e.window.Reset(entry.SourceIP)
		}
	}
}

func (e *Engine) ProcessSSH(ev *collector.SSHEvent) {
	for _, rule := range e.rules {
		if rule.Conditions.Source != "ssh_log" {
			continue
		}
		if rule.Conditions.EventType != "" && rule.Conditions.EventType != ev.EventType {
			continue
		}
		evidence := Evidence{Timestamp: ev.Timestamp, Raw: ev.Raw, MatchedRule: rule.ID}
		threshold := rule.Threshold
		if threshold == 0 {
			threshold = 20
		}
		total, evList, types := e.window.Add(ev.SourceIP, rule.Score, evidence, rule.Category)
		if total >= threshold {
			e.emit(ev.SourceIP, rule, evList, types)
			e.window.Reset(ev.SourceIP)
		}
	}
}

func (e *Engine) emit(ip string, rule Rule, evidence []Evidence, types []string) {
	inc := Incident{
		ID:         newID(),
		Type:       rule.Category,
		Severity:   ScoreToSeverity(rule.Score * len(evidence)),
		SourceIP:   ip,
		Score:      rule.Score * len(evidence),
		Evidence:   evidence,
		DetectedAt: time.Now(),
	}
	// Simple correlation: if multiple attack types seen, escalate
	if len(uniqueTypes(types)) >= 3 {
		inc.Correlated = true
		inc.Type = "exploit_chain"
		inc.Severity = SeverityCritical
	}
	select {
	case e.incidentC <- inc:
	default:
	}
}

func (e *Engine) matchLog(rule Rule, entry *collector.LogEntry) bool {
	c := rule.Conditions
	if c.Method != "" && !strings.EqualFold(c.Method, entry.Method) {
		return false
	}
	for _, p := range c.PathEquals {
		if strings.EqualFold(entry.Path, p) {
			return true
		}
	}
	for _, p := range c.PathContains {
		if strings.Contains(entry.Path, p) {
			return true
		}
	}
	for _, pattern := range c.QueryRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(entry.Query) {
			return true
		}
	}
	for _, ua := range c.UAContains {
		if strings.Contains(strings.ToLower(entry.UserAgent), strings.ToLower(ua)) {
			return true
		}
	}
	if c.StatusMin > 0 && c.StatusMax > 0 {
		if entry.StatusCode >= c.StatusMin && entry.StatusCode <= c.StatusMax {
			return true
		}
	}
	return false
}

func uniqueTypes(types []string) []string {
	seen := make(map[string]struct{})
	out := []string{}
	for _, t := range types {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("inc_%x", b)
}
