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
	rules      []Rule
	window     *IPWindow
	ruleWindow *RuleWindow
	incidentC  chan<- Incident
}

func NewEngine(rules []Rule, correlationWindow time.Duration, incidentC chan<- Incident) *Engine {
	return &Engine{
		rules:      rules,
		window:     NewIPWindow(correlationWindow),
		ruleWindow: NewRuleWindow(),
		incidentC:  incidentC,
	}
}

// addIsolated menghitung aturan Isolated di jendelanya sendiri dan
// mengeluarkan insiden tanpa korelasi. Lihat Rule.Isolated.
func (e *Engine) addIsolated(ip string, rule Rule, ev Evidence) {
	window := time.Duration(rule.Conditions.WindowSeconds) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}
	key := rule.ID + "|" + ip
	count, evidence := e.ruleWindow.Add(key, window, ev)
	threshold := rule.Threshold
	if threshold == 0 {
		threshold = 20
	}
	if count*rule.Score >= threshold {
		e.emit(ip, rule, evidence, []string{rule.Category})
		e.ruleWindow.Reset(key)
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
		ev := Evidence{Timestamp: entry.Timestamp, Host: entry.Host, Raw: entry.Raw, MatchedRule: rule.ID}
		if rule.Isolated {
			e.addIsolated(entry.SourceIP, rule, ev)
			continue
		}
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
		Mitre:      rule.Mitre,
		Evidence:   evidence,
		DetectedAt: time.Now(),
	}
	// Simple correlation: if multiple attack types seen, escalate
	if len(uniqueTypes(types)) >= 3 {
		inc.Correlated = true
		inc.Type = "exploit_chain"
		inc.Severity = SeverityCritical
		inc.Mitre = "" // exploit chain spans multiple techniques — no single ID
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

	// Condition matching uses AND between different field groups, OR within each group:
	//   path group  = PathEquals OR PathContains OR PathRegex  (any one is enough)
	//   query group = QueryRegex (any one is enough)
	//   ua group    = UAContains (any one is enough)
	//   status group = StatusMin/Max range check
	// When PathContains AND PathRegex are both specified, the path must satisfy
	// BOTH sub-groups (AND) — used for webshell upload: directory in path + .php extension.

	if !e.matchPathConditions(c, entry) {
		return false
	}

	// Extra conditions (query/UA/status): if specified, at least one must match.
	hasExtra := len(c.QueryRegex) > 0 || len(c.UAContains) > 0 || (c.StatusMin > 0 && c.StatusMax > 0)
	if hasExtra && !e.matchExtraConditions(c, entry) {
		return false
	}

	// Must have matched at least something — a rule with no conditions at all
	// would otherwise match every request and fire constantly.
	//
	// Exception: purely volumetric rules (per-IP counting over a window, e.g.
	// rule_request_flood) deliberately carry no path/query/UA/status condition.
	// Their selectivity comes from the count threshold, not from the shape of
	// any single request — a flood of plain "GET / 200" is exactly the case the
	// other rules cannot see. Treat PerIP as a valid condition of its own.
	hasPath := len(c.PathEquals) > 0 || len(c.PathContains) > 0 || len(c.PathRegex) > 0
	isVolumetric := c.PerIP && c.WindowSeconds > 0
	return hasPath || hasExtra || isVolumetric
}

// matchPathConditions checks path-based conditions.
// If both PathContains and PathRegex are set, BOTH must match (AND).
// PathEquals is always OR with the others.
func (e *Engine) matchPathConditions(c Conditions, entry *collector.LogEntry) bool {
	if len(c.PathEquals) == 0 && len(c.PathContains) == 0 && len(c.PathRegex) == 0 {
		return true // no path conditions — pass through
	}

	// PathEquals: any match → immediately true
	for _, p := range c.PathEquals {
		if strings.EqualFold(entry.Path, p) {
			return true
		}
	}

	// PathContains + PathRegex AND logic when both present
	if len(c.PathContains) > 0 && len(c.PathRegex) > 0 {
		containsOK := false
		for _, p := range c.PathContains {
			if strings.Contains(entry.Path, p) {
				containsOK = true
				break
			}
		}
		if !containsOK {
			return false
		}
		for _, pattern := range c.PathRegex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(entry.Path) {
				return true
			}
		}
		return false
	}

	// Only PathContains
	for _, p := range c.PathContains {
		if strings.Contains(entry.Path, p) {
			return true
		}
	}

	// Only PathRegex
	for _, pattern := range c.PathRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(entry.Path) {
			return true
		}
	}

	return false
}

func (e *Engine) matchExtraConditions(c Conditions, entry *collector.LogEntry) bool {
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
